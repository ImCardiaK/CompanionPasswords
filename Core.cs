using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Runtime.InteropServices;
using System.ComponentModel;

namespace CompanionPasswords {
    [DataContract] public sealed class Entry {
        [DataMember] public string Id = Guid.NewGuid().ToString("N");
        [DataMember] public string Name = "";
        [DataMember] public string Username = "";
        [DataMember] public string Password = "";
        [DataMember] public string Url = "";
        [DataMember] public string Notes = "";
        [DataMember] public string Category = "Personnel";
        [DataMember] public bool Favorite;
        [DataMember] public string Updated = DateTime.UtcNow.ToString("o");
        public Entry Copy() { return (Entry)MemberwiseClone(); }
    }

    [DataContract] sealed class VaultContent {
        [DataMember] public List<Entry> Entries;
        [DataMember] public List<string> Categories;
    }

    public sealed class Vault : IDisposable {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool MoveFileEx(string existing, string destination, int flags);
        // Fixed v1 profile: PBKDF2-HMAC-SHA256, 600,000 rounds, 32-byte salt;
        // AES-256-CBC + HMAC-SHA256 encrypt-then-MAC, independent subkeys.
        static readonly byte[] Magic = Encoding.ASCII.GetBytes("CPVAULT2");
        static readonly byte[] LegacyMagic = Encoding.ASCII.GetBytes("CPVAULT1");
        const int MaxSize = 16 * 1024 * 1024;
        byte[] keys;
        byte[] salt;
        public readonly string Path;
        public List<Entry> Entries { get; private set; }
        public List<string> Categories { get; private set; }
        public bool IsOpen { get { return keys != null; } }
        public Vault(string path) { Path = path; Entries = new List<Entry>(); Categories = new List<string>(); }
        public static byte[] Random(int count) {
            var bytes = new byte[count];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(bytes);
            return bytes;
        }
        static byte[] Derive(string password, byte[] salt) {
            using (var kdf = new Rfc2898DeriveBytes(password, salt, 600000, HashAlgorithmName.SHA256))
                return kdf.GetBytes(64);
        }
        public void Create(string password) {
            if (File.Exists(Path)) throw new IOException("Un coffre existe déjà.");
            ValidateMaster(password);
            Categories = new List<string> { "Personnel", "Travail", "Autre" };
            salt = Random(32); keys = Derive(password, salt);
            try { Save(new List<Entry>()); } catch { Lock(); throw; }
        }
        public static void ValidateMaster(string password) {
            if (password.Length < 14 || String.IsNullOrWhiteSpace(password))
                throw new InvalidOperationException("Choisissez une phrase secrète d’au moins 14 caractères.");
        }
        public static byte[] ReadRaw(string path) {
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read)) {
                if (stream.Length > MaxSize) throw new InvalidDataException("Le fichier dépasse la limite de 16 Mo.");
                var data = new byte[(int)stream.Length];
                int n = 0, got;
                while (n < data.Length && (got = stream.Read(data, n, data.Length - n)) > 0) n += got;
                if (n != data.Length) throw new InvalidDataException("Lecture du fichier incomplète.");
                return data;
            }
        }
        public static byte[] Read(string path) {
            var data = ReadRaw(path);
            if (data.Length < 104 || (!data.Take(8).SequenceEqual(Magic) && !data.Take(8).SequenceEqual(LegacyMagic))) throw new InvalidDataException("Format de coffre invalide.");
            return data;
        }
        public void Unlock(string password) {
            Lock();
            byte[] data = Read(Path), candidate = null, plaintext = null;
            var fileSalt = data.Skip(8).Take(32).ToArray();
            try {
                candidate = Derive(password, fileSalt);
                byte[] expected;
                using (var mac = new HMACSHA256(candidate.Skip(32).ToArray()))
                    expected = mac.ComputeHash(data, 0, data.Length - 32);
                int mismatch = 0;
                for (int i = 0; i < 32; i++) mismatch |= expected[i] ^ data[data.Length - 32 + i];
                if (mismatch != 0) throw new CryptographicException("Mot de passe incorrect ou coffre endommagé.");
                using (var aes = Aes.Create()) {
                    aes.Key = candidate.Take(32).ToArray(); aes.IV = data.Skip(40).Take(16).ToArray();
                    aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
                    using (var dec = aes.CreateDecryptor()) plaintext = dec.TransformFinalBlock(data, 56, data.Length - 88);
                }
                using (var stream = new MemoryStream(plaintext)) {
                    VaultContent content;
                    if (data.Take(8).SequenceEqual(LegacyMagic)) {
                        var entries = (List<Entry>)new DataContractJsonSerializer(typeof(List<Entry>)).ReadObject(stream);
                        Validate(entries);
                        content = new VaultContent { Entries = entries, Categories = new[] { "Personnel", "Travail", "Autre" }.Concat(entries.Select(e => e.Category).Where(c => c.Length > 0)).Distinct(StringComparer.OrdinalIgnoreCase).ToList() };
                    } else content = (VaultContent)new DataContractJsonSerializer(typeof(VaultContent)).ReadObject(stream);
                    if (content == null) throw new InvalidDataException("Contenu du coffre invalide.");
                    Validate(content.Entries);
                    ValidateCategories(content.Categories, content.Entries);
                    Entries = content.Entries; Categories = content.Categories;
                }
                salt = fileSalt; keys = candidate; candidate = null;
            } finally {
                if (candidate != null) Array.Clear(candidate, 0, candidate.Length);
                if (plaintext != null) Array.Clear(plaintext, 0, plaintext.Length);
            }
        }
        static void Validate(List<Entry> entries) {
            if (entries == null || entries.Any(e => e == null || e.Id == null || e.Name == null || e.Password == null || e.Username == null || e.Url == null || e.Notes == null || e.Category == null || e.Updated == null) || entries.Select(e => e.Id).Distinct().Count() != entries.Count)
                throw new InvalidDataException("Contenu du coffre invalide.");
        }
        static void ValidateCategories(List<string> categories, List<Entry> entries) {
            if (categories == null || categories.Any(c => String.IsNullOrWhiteSpace(c) || c.Length > 80 || c != c.Trim() || c.Any(Char.IsControl)) || categories.Distinct(StringComparer.OrdinalIgnoreCase).Count() != categories.Count || entries.Any(e => e.Category.Length > 0 && !categories.Contains(e.Category)))
                throw new InvalidDataException("Les catégories du coffre sont invalides.");
        }
        byte[] Encrypt(List<Entry> entries, List<string> categories) {
            Validate(entries);
            ValidateCategories(categories, entries);
            byte[] plain;
            using (var stream = new MemoryStream()) {
                new DataContractJsonSerializer(typeof(VaultContent)).WriteObject(stream, new VaultContent { Entries = entries, Categories = categories }); plain = stream.ToArray();
            }
            try {
                using (var aes = Aes.Create()) {
                    aes.Key = keys.Take(32).ToArray(); aes.GenerateIV(); aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
                    byte[] cipher;
                    using (var enc = aes.CreateEncryptor()) cipher = enc.TransformFinalBlock(plain, 0, plain.Length);
                    var body = Magic.Concat(salt).Concat(aes.IV).Concat(cipher).ToArray();
                    using (var mac = new HMACSHA256(keys.Skip(32).ToArray())) return body.Concat(mac.ComputeHash(body)).ToArray();
                }
            } finally { Array.Clear(plain, 0, plain.Length); }
        }
        public static void AtomicWrite(string path, byte[] bytes, string backup) {
            var directory = System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(path));
            Directory.CreateDirectory(directory);
            var temp = System.IO.Path.Combine(directory, ".companion-" + Guid.NewGuid().ToString("N") + ".tmp");
            try {
                using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None)) {
                    stream.Write(bytes, 0, bytes.Length); stream.Flush(true);
                }
                if (File.Exists(path) && backup != null) AtomicWrite(backup, ReadRaw(path), null);
                // Same-volume atomic rename, preserving the temp file's inherited directory ACL.
                // Unlike ReplaceFile this does not require WRITE_DAC to merge destination ACLs.
                if (!MoveFileEx(temp, path, 0x1 | 0x8)) throw new IOException("Échec du remplacement atomique du coffre.", new Win32Exception(Marshal.GetLastWin32Error()));
            } finally { if (File.Exists(temp)) File.Delete(temp); }
        }
        public void Save(List<Entry> entries) {
            SaveState(entries, Categories);
        }
        void SaveState(List<Entry> entries, List<string> categories) {
            if (!IsOpen) throw new InvalidOperationException("Le coffre est verrouillé.");
            var data = Encrypt(entries, categories);
            if (data.Length > MaxSize) throw new InvalidOperationException("Le coffre dépasse la limite de 16 Mo.");
            AtomicWrite(Path, data, Path + ".bak");
            Entries = entries; Categories = categories;
        }
        string CategoryName(string name, string except = null) {
            if (!IsOpen) throw new InvalidOperationException("Le coffre est verrouillé.");
            name = (name ?? "").Trim();
            if (name.Length == 0 || name.Length > 80 || name.Any(Char.IsControl)) throw new InvalidOperationException("Saisissez un nom de catégorie de 1 à 80 caractères, sur une seule ligne.");
            if (String.Equals(name, "Sans catégorie", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Ce nom est réservé aux identifiants sans catégorie.");
            if (Categories.Any(c => c != except && String.Equals(c, name, StringComparison.OrdinalIgnoreCase))) throw new InvalidOperationException("Une catégorie porte déjà ce nom.");
            return name;
        }
        public void AddCategory(string name) {
            name = CategoryName(name);
            SaveState(Entries, Categories.Concat(new[] { name }).ToList());
        }
        public void RenameCategory(string previous, string name) {
            name = CategoryName(name, previous);
            if (!Categories.Contains(previous)) throw new InvalidOperationException("Sélectionnez une catégorie existante.");
            var entries = Entries.Select(e => { if (e.Category != previous) return e; var copy = e.Copy(); copy.Category = name; copy.Updated = DateTime.UtcNow.ToString("o"); return copy; }).ToList();
            SaveState(entries, Categories.Select(c => c == previous ? name : c).ToList());
        }
        public void DeleteCategory(string name) {
            if (!IsOpen) throw new InvalidOperationException("Le coffre est verrouillé.");
            if (!Categories.Contains(name)) throw new InvalidOperationException("Sélectionnez une catégorie existante.");
            var entries = Entries.Select(e => { if (e.Category != name) return e; var copy = e.Copy(); copy.Category = ""; copy.Updated = DateTime.UtcNow.ToString("o"); return copy; }).ToList();
            SaveState(entries, Categories.Where(c => c != name).ToList());
        }
        public void ChangeMaster(string password) {
            if (!IsOpen) throw new InvalidOperationException("Le coffre est verrouillé.");
            ValidateMaster(password);
            byte[] oldKeys = keys, oldSalt = salt;
            byte[] nextSalt = Random(32), nextKeys = Derive(password, nextSalt);
            keys = nextKeys; salt = nextSalt;
            try { Save(Entries); }
            catch { Array.Clear(keys, 0, keys.Length); keys = oldKeys; salt = oldSalt; throw; }
            Array.Clear(oldKeys, 0, oldKeys.Length);
        }
        public void Export(string destination) {
            if (String.Equals(System.IO.Path.GetFullPath(destination), System.IO.Path.GetFullPath(Path), StringComparison.OrdinalIgnoreCase) || String.Equals(System.IO.Path.GetFullPath(destination), System.IO.Path.GetFullPath(Path + ".bak"), StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Choisissez un autre emplacement pour la sauvegarde.");
            AtomicWrite(destination, Read(Path), null);
        }
        public void Lock() {
            if (keys != null) Array.Clear(keys, 0, keys.Length);
            keys = null; salt = null; Entries = new List<Entry>(); Categories = new List<string>();
        }
        public void Dispose() { Lock(); }
        public static string Generate(int length) {
            if (length < 16 || length > 128) throw new ArgumentOutOfRangeException("length");
            const string alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%&*+-=?";
            for (;;) {
                var result = new StringBuilder();
                using (var rng = RandomNumberGenerator.Create()) {
                    byte[] b = new byte[1]; int limit = 256 - 256 % alphabet.Length;
                    while (result.Length < length) { rng.GetBytes(b); if (b[0] < limit) result.Append(alphabet[b[0] % alphabet.Length]); }
                }
                var s = result.ToString();
                if (s.Any(Char.IsLower) && s.Any(Char.IsUpper) && s.Any(Char.IsDigit) && s.Any(c => !Char.IsLetterOrDigit(c))) return s;
            }
        }
    }
}
