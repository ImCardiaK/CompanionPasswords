using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Runtime.Serialization.Json;

namespace CompanionPasswords {
    public static class Tests {
        static int assertions;
        static void Check(bool condition, string message) { if (!condition) throw new Exception(message); assertions++; }
        static void Reject(Action action, string message) { bool rejected = false; try { action(); } catch (CryptographicException) { rejected = true; } catch (InvalidDataException) { rejected = true; } Check(rejected, message); }
        static void Invalid(Action action, string message) { bool rejected = false; try { action(); } catch (InvalidOperationException) { rejected = true; } Check(rejected, message); }
        static void LegacyFixture(string path, string password, Entry entry) {
            byte[] salt = Vault.Random(32), keys;
            using (var kdf = new Rfc2898DeriveBytes(password, salt, 600000, HashAlgorithmName.SHA256)) keys = kdf.GetBytes(64);
            using (var aes = Aes.Create()) using (var stream = new MemoryStream()) {
                new DataContractJsonSerializer(typeof(List<Entry>)).WriteObject(stream, new List<Entry> { entry });
                aes.Key = keys.Take(32).ToArray(); aes.GenerateIV();
                byte[] plain = stream.ToArray(), cipher;
                using (var encrypt = aes.CreateEncryptor()) cipher = encrypt.TransformFinalBlock(plain, 0, plain.Length);
                var body = Encoding.ASCII.GetBytes("CPVAULT1").Concat(salt).Concat(aes.IV).Concat(cipher).ToArray();
                using (var mac = new HMACSHA256(keys.Skip(32).ToArray())) File.WriteAllBytes(path, body.Concat(mac.ComputeHash(body)).ToArray());
            }
            Array.Clear(keys, 0, keys.Length);
        }
        public static int Run() {
            string dir = System.IO.Path.Combine(Environment.CurrentDirectory, "artifacts", "CompanionTests-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir); var log = new StringBuilder();
            File.WriteAllText("artifacts/core-tests.txt", "RUNNING: security and persistence tests.\r\n");
            try {
                string path = System.IO.Path.Combine(dir, "vault.cpvault");
                const string master = "Phrase-secrete-test-2026!";
                var entry = new Entry { Name = "Instagram privé 漢字", Username = "test@example.test", Password = "UNIQUE_SECRET_!!_à漢字", Notes = "Notes secrètes\nDeuxième ligne" };
                using (var vault = new Vault(path)) {
                    vault.Create(master); Check(vault.IsOpen, "Create");
                    vault.Save(new List<Entry> { entry });
                    byte[] first = File.ReadAllBytes(path);
                    string raw = Encoding.UTF8.GetString(first);
                    Check(!raw.Contains(entry.Password) && !raw.Contains("Instagram") && !raw.Contains(entry.Username) && !raw.Contains(master), "No plaintext on disk");
                    vault.Save(vault.Entries); Check(!first.SequenceEqual(File.ReadAllBytes(path)), "Fresh IV on each save");
                    Check(first.SequenceEqual(File.ReadAllBytes(path + ".bak")), "Previous encrypted revision retained");
                    bool existingRejected = false; try { vault.Create(master); } catch (IOException) { existingRejected = true; } Check(existingRejected, "Existing vault cannot be overwritten by create");
                    byte[] beforeFailure = File.ReadAllBytes(path);
                    var huge = entry.Copy(); huge.Notes = new string('x', 17 * 1024 * 1024);
                    bool sizeRejected = false; try { vault.Save(new List<Entry> { huge }); } catch (InvalidOperationException) { sizeRejected = true; }
                    Check(sizeRejected && beforeFailure.SequenceEqual(File.ReadAllBytes(path)) && vault.Entries[0].Notes == entry.Notes, "Failed save preserves disk and session");
                    vault.AddCategory("  Jeux privés  ");
                    Check(vault.Categories.Contains("Jeux privés"), "Custom empty category created and trimmed");
                    Invalid(delegate { vault.AddCategory("JEUX PRIVÉS"); }, "Case-insensitive duplicates rejected");
                    Invalid(delegate { vault.AddCategory("   "); }, "Blank category rejected");
                    Invalid(delegate { vault.AddCategory(new string('x', 81)); }, "Long category rejected");
                    Invalid(delegate { vault.RenameCategory("Personnel", "Travail"); }, "Rename collision rejected");
                    var beforeRename = File.ReadAllBytes(path);
                    using (var held = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None)) {
                        bool failed = false; try { vault.RenameCategory("Personnel", "Échec simulé"); } catch (IOException) { failed = true; }
                        Check(failed && vault.Categories.Contains("Personnel") && vault.Entries[0].Category == "Personnel", "Failed category write leaves session intact");
                    }
                    Check(beforeRename.SequenceEqual(File.ReadAllBytes(path)), "Failed category write leaves file intact");
                    vault.RenameCategory("Personnel", "Comptes");
                    Check(vault.Entries[0].Category == "Comptes" && vault.Entries[0].Password == entry.Password, "Rename updates assignments without altering secrets");
                    vault.DeleteCategory("Travail");
                    Check(!vault.Categories.Contains("Travail"), "Default category can be deleted");
                    Check(!Encoding.UTF8.GetString(File.ReadAllBytes(path)).Contains("Jeux privés"), "Category names encrypted");
                    vault.Lock(); Check(!vault.IsOpen && vault.Entries.Count == 0, "Lock clears session");
                    Check(vault.Categories.Count == 0, "Lock clears categories");
                    Invalid(delegate { vault.AddCategory("Verrouillé"); }, "Locked category edits rejected");
                    bool lockedRejected = false; try { vault.Save(new List<Entry>()); } catch (InvalidOperationException) { lockedRejected = true; } Check(lockedRejected, "Locked save rejected");
                    Reject(delegate { vault.Unlock("wrong"); }, "Wrong password rejected"); Check(!vault.IsOpen, "Failed unlock remains locked");
                    vault.Unlock(master); Check(vault.Entries.Count == 1 && vault.Entries[0].Password == entry.Password && vault.Entries[0].Notes == entry.Notes, "Unicode round trip");
                    Check(vault.Categories.Contains("Jeux privés") && !vault.Categories.Contains("Travail") && vault.Entries[0].Category == "Comptes", "Empty categories, deletion and renamed assignments persist");
                    string export = System.IO.Path.Combine(dir, "export.cpvault"); vault.Export(export); Check(File.ReadAllBytes(export).SequenceEqual(File.ReadAllBytes(path)), "Encrypted export exact");
                    using (var restored = new Vault(export)) { restored.Unlock(master); Check(restored.Entries[0].Name == entry.Name, "Backup readable"); Check(restored.Categories.SequenceEqual(vault.Categories), "Backup preserves categories"); }
                    var edited = vault.Entries[0].Copy(); edited.Password = "Updated-secret-123!"; vault.Save(new List<Entry> { edited });
                    vault.Lock(); vault.Unlock(master); Check(vault.Entries[0].Password == edited.Password, "Edit persists");
                    vault.ChangeMaster("Nouvelle-phrase-test-2026!"); vault.Lock();
                    Reject(delegate { vault.Unlock(master); }, "Old master rejected after rotation");
                    vault.Unlock("Nouvelle-phrase-test-2026!"); Check(vault.Entries[0].Password == edited.Password, "Master rotation preserves entries");
                    Check(vault.Categories.Contains("Jeux privés"), "Master rotation preserves categories");
                    vault.DeleteCategory("Comptes");
                    Check(vault.Entries.Count == 1 && vault.Entries[0].Category == "" && vault.Entries[0].Password == edited.Password, "Deleting an occupied category keeps its secrets uncategorized");
                    foreach (var category in vault.Categories.ToList()) vault.DeleteCategory(category);
                    vault.Save(new List<Entry>()); vault.Lock(); vault.Unlock("Nouvelle-phrase-test-2026!"); Check(vault.Entries.Count == 0, "Delete persists");
                    Check(vault.Categories.Count == 0, "Deleting all categories persists without recreating defaults");
                }
                string legacy = System.IO.Path.Combine(dir, "legacy.cpvault"); LegacyFixture(legacy, master, entry);
                using (var migrated = new Vault(legacy)) {
                    migrated.Unlock(master); Check(migrated.Entries[0].Password == entry.Password && migrated.Categories.Contains("Personnel"), "Original v1 vault opens without losing secrets");
                    migrated.AddCategory("Migrée"); Check(Encoding.ASCII.GetString(File.ReadAllBytes(legacy), 0, 8) == "CPVAULT2", "First save migrates to v2");
                    Check(Encoding.ASCII.GetString(File.ReadAllBytes(legacy + ".bak"), 0, 8) == "CPVAULT1", "Migration retains previous encrypted v1 revision");
                    migrated.Lock(); migrated.Unlock(master); Check(migrated.Categories.Contains("Migrée") && migrated.Entries[0].Password == entry.Password, "Migrated vault reopens");
                }
                byte[] original = File.ReadAllBytes(path);
                foreach (int offset in new[] { 8, 40, 56, original.Length - 1 }) {
                    byte[] damaged = (byte[])original.Clone(); damaged[offset] ^= 1; File.WriteAllBytes(path, damaged);
                    using (var vault = new Vault(path)) Reject(delegate { vault.Unlock("Nouvelle-phrase-test-2026!"); }, "Tampering rejected at " + offset);
                }
                File.WriteAllBytes(path, original.Take(72).ToArray());
                using (var vault = new Vault(path)) Reject(delegate { vault.Unlock(master); }, "Truncation rejected");
                File.WriteAllBytes(path, new byte[104]); using (var vault = new Vault(path)) Reject(delegate { vault.Unlock(master); }, "Invalid header rejected");
                Vault.AtomicWrite(path, original, path + ".bak");
                Check(File.ReadAllBytes(path).SequenceEqual(original) && File.ReadAllBytes(path + ".bak").All(b => b == 0), "Recovery can replace a corrupt vault and preserve it");
                for (int i = 0; i < 100; i++) { string generated = Vault.Generate(24); Check(generated.Length == 24 && generated.Any(Char.IsUpper) && generated.Any(Char.IsLower) && generated.Any(Char.IsDigit) && generated.Any(c => !Char.IsLetterOrDigit(c)), "Generator constraints"); }
                Check(Enumerable.Range(0, 100).Select(i => Vault.Generate(24)).Distinct().Count() == 100, "Generator uniqueness sample");
                log.AppendLine("PASS: " + assertions + " assertions. Encryption, persistence, categories CRUD/validation/failed-write rollback, empty categories, backup, master rotation, legacy v1 migration, tampering rejection, generator.");
                Directory.CreateDirectory("artifacts"); File.WriteAllText("artifacts/core-tests.txt", log.ToString()); return 0;
            } catch (Exception ex) { Directory.CreateDirectory("artifacts"); File.WriteAllText("artifacts/core-tests.txt", "FAIL: " + ex); return 1; }
            finally { Directory.Delete(dir, true); }
        }
    }
}
