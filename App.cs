using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Microsoft.Win32;

namespace CompanionPasswords {
    static class Program {
        [STAThread] static int Main(string[] args) {
            if (args.Contains("--self-test")) return Tests.Run();
            bool smoke = args.Contains("--smoke-test");
            var app = new Application();
            using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("Theme.xaml"))
                app.Resources.MergedDictionaries.Add((ResourceDictionary)XamlReader.Load(stream));
            string dir = smoke ? System.IO.Path.Combine(Environment.CurrentDirectory, "artifacts", "CompanionSmoke-" + Guid.NewGuid().ToString("N")) : System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CompanionPasswords");
            try {
                Directory.CreateDirectory(dir);
                var acl = new DirectorySecurity();
                acl.SetAccessRuleProtection(true, false);
                acl.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                if (!smoke) Directory.SetAccessControl(dir, acl);
                using (var single = new FileStream(System.IO.Path.Combine(dir, "session.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None)) {
                    var window = new MainWindow(new Vault(System.IO.Path.Combine(dir, "vault.cpvault")), smoke);
                    app.Run(window);
                }
                if (smoke) Directory.Delete(dir, true);
                return 0;
            } catch (Exception ex) {
                if (smoke) { Directory.CreateDirectory("artifacts"); File.WriteAllText("artifacts/ui-tests.txt", "FAIL startup: " + ex); return 1; }
                MessageBox.Show("CompanionPasswords ne peut pas démarrer. Vérifiez qu’il n’est pas déjà ouvert et que votre dossier utilisateur est accessible.\n\n" + ex.Message, "CompanionPasswords", MessageBoxButton.OK, MessageBoxImage.Error);
                return 1;
            }
        }
    }

    public sealed class MainWindow : Window {
        readonly Vault vault;
        readonly bool smoke;
        readonly DispatcherTimer clock = new DispatcherTimer();
        DateTime activity = DateTime.UtcNow, copiedAt, revealUntil, retryAt;
        int failures;
        string copied, filter = "Tous";
        bool categoryFilter;
        TextBox search;
        ListBox list;
        StackPanel details;
        TextBlock count, status, secretLabel;
        Entry selected;
        Window modal;
        bool busy, pendingLock;
        IntPtr handle;
        [DllImport("user32.dll")] static extern bool SetWindowDisplayAffinity(IntPtr hwnd, uint affinity);
        [DllImport("wtsapi32.dll")] static extern bool WTSRegisterSessionNotification(IntPtr hwnd, int flags);
        [DllImport("wtsapi32.dll")] static extern bool WTSUnRegisterSessionNotification(IntPtr hwnd);

        public MainWindow(Vault v, bool test) {
            vault = v; smoke = test;
            Style = (Style)Application.Current.FindResource(typeof(Window));
            Title = "CompanionPasswords"; Width = 1180; Height = 790; MinWidth = 980; MinHeight = 680;
            WindowStartupLocation = WindowStartupLocation.CenterScreen;
            using (var icon = Assembly.GetExecutingAssembly().GetManifestResourceStream("app.ico")) { Icon = BitmapFrame.Create(icon, BitmapCreateOptions.None, BitmapCacheOption.OnLoad); }
            SourceInitialized += delegate {
                handle = new WindowInteropHelper(this).Handle;
                HwndSource.FromHwnd(handle).AddHook(NativeMessage);
                WTSRegisterSessionNotification(handle, 0);
                if (!smoke) SetWindowDisplayAffinity(handle, 0x11);
            };
            PreviewKeyDown += delegate(object s, KeyEventArgs e) {
                activity = DateTime.UtcNow;
                if (e.Key == Key.L && (Keyboard.Modifiers & ModifierKeys.Control) != 0) { Lock(); e.Handled = true; }
                if (vault.IsOpen && !busy && modal == null && e.Key == Key.N && (Keyboard.Modifiers & ModifierKeys.Control) != 0) { Edit(null); e.Handled = true; }
            };
            PreviewMouseDown += delegate { activity = DateTime.UtcNow; };
            PreviewMouseWheel += delegate { activity = DateTime.UtcNow; };
            StateChanged += delegate { if (WindowState == WindowState.Minimized) Lock(); };
            Deactivated += delegate { HideSecret(); };
            Closing += delegate(object s, System.ComponentModel.CancelEventArgs e) { if (busy) e.Cancel = true; };
            Closed += delegate { clock.Stop(); ClearClipboard(); vault.Dispose(); if (handle != IntPtr.Zero) WTSUnRegisterSessionNotification(handle); };
            clock.Interval = TimeSpan.FromSeconds(1);
            clock.Tick += delegate {
                if (copied != null && DateTime.UtcNow - copiedAt >= TimeSpan.FromSeconds(20)) ClearClipboard();
                if (secretLabel != null && DateTime.UtcNow >= revealUntil) HideSecret();
                if (vault.IsOpen && DateTime.UtcNow - activity > TimeSpan.FromMinutes(2)) Lock();
            };
            clock.Start(); ShowLogin();
            if (smoke) Loaded += async delegate { await Smoke(); };
        }
        IntPtr NativeMessage(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled) {
            if ((msg == 0x02B1 && wParam.ToInt32() == 7) || (msg == 0x0218 && wParam.ToInt32() == 4)) Lock();
            return IntPtr.Zero;
        }
        public static SolidColorBrush Brush(string color) { return (SolidColorBrush)new BrushConverter().ConvertFromString(color); }
        public static TextBlock Text(string text, double size = 14, string color = "#EDF3FF") {
            return new TextBlock { Text = text, FontSize = size, Foreground = Brush(color), Margin = new Thickness(0, 0, 0, 10) };
        }
        public static Button Button(string title, Action action, bool primary = false) {
            var button = new Button { Content = title };
            if (primary) { button.Background = Brush("#6D9CFF"); button.Foreground = Brush("#081224"); button.FontWeight = FontWeights.SemiBold; }
            button.Click += delegate { action(); }; return button;
        }
        static Border Card(UIElement child, double padding = 24) { return new Border { Background = Brush("#141E30"), BorderBrush = Brush("#25324A"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(16), Padding = new Thickness(padding), Child = child }; }
        public static TextBox Field(Panel panel, string label, string value = "") {
            panel.Children.Add(Text(label, 12, "#A9B8D0"));
            var box = new TextBox { Text = value, MaxLength = 4096 }; panel.Children.Add(box); return box;
        }
        public static PasswordBox Secret(Panel panel, string label) {
            panel.Children.Add(Text(label, 12, "#A9B8D0")); var box = new PasswordBox { MaxLength = 4096 }; panel.Children.Add(box); return box;
        }
        void Error(Exception ex) {
            string message = ex is CryptographicException ? "Mot de passe incorrect ou coffre endommagé." : ex is System.Runtime.Serialization.SerializationException ? "Le contenu du coffre est invalide." : ex is UnauthorizedAccessException ? "Accès au fichier refusé. Vérifiez les droits du dossier." : ex is IOException ? "Impossible d’accéder au fichier. Vérifiez son emplacement et l’espace disponible." : ex.Message;
            MessageBox.Show(modal ?? this, message, "CompanionPasswords", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        void ShowLogin() {
            bool creating = !File.Exists(vault.Path);
            var grid = new Grid { Margin = new Thickness(56) };
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(430) });
            var left = new StackPanel { VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 55, 0) };
            left.Children.Add(Text("C /  COMPANION", 18, "#87ACFF"));
            left.Children.Add(Text("Vos mots de passe.\nVotre espace privé.", 42));
            left.Children.Add(Text("Un seul coffre pour vos sites, applications\net tout ce qui compte pour vous.", 17, "#A5B5CF"));
            left.Children.Add(new Border { Height = 30 });
            left.Children.Add(Text("01    Un coffre chiffré sur votre PC", 15));
            left.Children.Add(Text("02    Aucun compte, aucun cloud", 15));
            left.Children.Add(Text("03    Des mots de passe uniques, en un clic", 15));
            left.Children.Add(new Border { Height = 40 });
            left.Children.Add(Text("COMPANION PASSWORDS    /    VERSION 1.1", 11, "#7385A3")); grid.Children.Add(left);
            var form = new StackPanel();
            form.Children.Add(Text(creating ? "BIENVENUE CHEZ VOUS" : "VOTRE ESPACE PRIVÉ", 11, "#81ABFF"));
            form.Children.Add(Text(creating ? "Créer votre coffre" : "Bon retour.", 29));
            form.Children.Add(Text(creating ? "Choisissez une phrase secrète longue et unique. Elle sera la clé de votre coffre." : "Saisissez votre mot de passe principal pour retrouver vos identifiants.", 14, "#A5B5CF"));
            var password = Secret(form, "Mot de passe principal");
            PasswordBox confirm = creating ? Secret(form, "Confirmer le mot de passe principal") : null;
            var feedback = Text("", 12, "#FFA8AB");
            Button submit = null;
            Action unlock = async delegate {
                if (busy) return;
                if (DateTime.UtcNow < retryAt) { feedback.Text = "Patientez quelques secondes avant de réessayer."; return; }
                if (creating && password.Password != confirm.Password) { feedback.Text = "Les deux mots de passe ne correspondent pas."; return; }
                string master = password.Password;
                if (creating) { try { Vault.ValidateMaster(master); } catch (Exception ex) { feedback.Text = ex.Message; return; } }
                busy = true; submit.IsEnabled = false; password.IsEnabled = false;
                if (confirm != null) confirm.IsEnabled = false;
                feedback.Foreground = Brush("#A5B5CF"); feedback.Text = "Ouverture sécurisée du coffre…";
                password.Clear(); if (confirm != null) confirm.Clear();
                try {
                    await Task.Run(delegate { if (creating) vault.Create(master); else vault.Unlock(master); });
                    failures = 0; activity = DateTime.UtcNow;
                    if (!pendingLock) ShowVault();
                } catch (Exception ex) {
                    failures++; retryAt = DateTime.UtcNow.AddSeconds(Math.Min(30, failures * 2));
                    feedback.Foreground = Brush("#FFA8AB");
                    feedback.Text = ex is CryptographicException ? "Mot de passe incorrect ou coffre endommagé." : "Ouverture impossible : " + ex.Message;
                } finally {
                    master = null; busy = false; submit.IsEnabled = true; password.IsEnabled = true;
                    if (confirm != null) confirm.IsEnabled = true;
                    if (pendingLock) { pendingLock = false; Lock(); }
                }
            };
            submit = Button(creating ? "Créer mon coffre   →" : "Déverrouiller   →", unlock, true);
            form.Children.Add(submit); form.Children.Add(feedback);
            password.KeyDown += delegate(object s, KeyEventArgs e) { if (e.Key == Key.Enter) unlock(); };
            if (confirm != null) confirm.KeyDown += delegate(object s, KeyEventArgs e) { if (e.Key == Key.Enter) unlock(); };
            form.Children.Add(Text(creating ? "14 caractères minimum. Conservez cette phrase en lieu sûr : aucune récupération n’est possible si vous l’oubliez." : "Le coffre se verrouille après 2 minutes sans activité et lorsque vous réduisez la fenêtre.", 12, "#91A4C1"));
            form.Children.Add(Button("Restaurer une sauvegarde chiffrée", Restore));
            var card = Card(form, 30); card.VerticalAlignment = VerticalAlignment.Center; Grid.SetColumn(card, 1); grid.Children.Add(card);
            Content = grid; Dispatcher.BeginInvoke(new Action(delegate { password.Focus(); }));
        }
        void ShowVault() {
            var root = new Grid(); root.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(224) }); root.ColumnDefinitions.Add(new ColumnDefinition());
            var sidebar = new DockPanel { Margin = new Thickness(20, 28, 16, 24) };
            var bottom = new StackPanel();
            bottom.Children.Add(Text("●  Stockage local chiffré", 12, "#78DABC"));
            bottom.Children.Add(Text("Verrouillage après 2 min\nPresse-papiers effacé après 20 s", 11, "#94A5BF"));
            bottom.Children.Add(Button("Verrouiller    Ctrl+L", Lock)); DockPanel.SetDock(bottom, Dock.Bottom); sidebar.Children.Add(bottom);
            var nav = new StackPanel(); nav.Children.Add(Text("C /", 38, "#86AAFF")); nav.Children.Add(Text("Companion\nPasswords", 23)); nav.Children.Add(new Border { Height = 30 }); nav.Children.Add(Text("VOTRE BIBLIOTHÈQUE", 10, "#8092B0"));
            foreach (var name in new[] { "Tous", "Favoris" }) { var n = name; nav.Children.Add(Button((n == "Favoris" ? "☆   " : "▤   ") + n, delegate { filter = n; categoryFilter = false; Refresh(); })); }
            nav.Children.Add(Button("Gérer les catégories", ManageCategories));
            foreach (var name in vault.Categories.Concat(new[] { "" })) { var n = name; nav.Children.Add(Button("▤   " + CategoryLabel(n), delegate { filter = n; categoryFilter = true; Refresh(); })); }
            nav.Children.Add(new Border { Height = 22 }); nav.Children.Add(Text("OUTILS", 10, "#8092B0"));
            nav.Children.Add(Button("Générateur", Generator)); nav.Children.Add(Button("Sauvegarder", Export)); nav.Children.Add(Button("Sécurité", Security)); sidebar.Children.Add(new ScrollViewer { Content = nav, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled });
            foreach (var navButton in nav.Children.OfType<Button>()) navButton.Padding = new Thickness(16, 8, 16, 8);
            var sideBorder = new Border { Background = Brush("#101A2B"), BorderBrush = Brush("#24324A"), BorderThickness = new Thickness(0, 0, 1, 0), Child = sidebar }; root.Children.Add(sideBorder);
            var main = new Grid { Margin = new Thickness(30) }; Grid.SetColumn(main, 1); root.Children.Add(main);
            main.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); main.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); main.RowDefinitions.Add(new RowDefinition()); main.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            var top = new DockPanel(); var add = Button("＋  Ajouter un identifiant", delegate { Edit(null); }, true); add.VerticalAlignment = VerticalAlignment.Top; DockPanel.SetDock(add, Dock.Right); top.Children.Add(add);
            var heading = new StackPanel(); heading.Children.Add(Text("Mon coffre", 30)); count = Text("", 13, "#94A5BF"); heading.Children.Add(count); top.Children.Add(heading); main.Children.Add(top);
            var searchContainer = new Grid { Margin = new Thickness(0, 18, 0, 22) };
            search = new TextBox { ToolTip = "Rechercher par nom, identifiant, site ou catégorie", Margin = new Thickness(0) };
            var placeholder = Text("Rechercher dans le coffre…", 14, "#8194B2"); placeholder.Margin = new Thickness(13, 0, 0, 0); placeholder.VerticalAlignment = VerticalAlignment.Center; placeholder.IsHitTestVisible = false;
            search.TextChanged += delegate { placeholder.Visibility = search.Text.Length == 0 ? Visibility.Visible : Visibility.Collapsed; Refresh(); };
            searchContainer.Children.Add(search); searchContainer.Children.Add(placeholder); Grid.SetRow(searchContainer, 1); main.Children.Add(searchContainer);
            var body = new Grid(); body.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(0.9, GridUnitType.Star) }); body.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1.1, GridUnitType.Star) }); Grid.SetRow(body, 2); main.Children.Add(body);
            list = new ListBox(); list.SelectionChanged += delegate { var item = list.SelectedItem as ListBoxItem; selected = item == null ? null : item.Tag as Entry; ShowDetails(); }; body.Children.Add(list);
            details = new StackPanel(); var detailCard = Card(new ScrollViewer { Content = details, VerticalScrollBarVisibility = ScrollBarVisibility.Auto }, 24); detailCard.Margin = new Thickness(14, 0, 0, 0); Grid.SetColumn(detailCard, 1); body.Children.Add(detailCard);
            status = Text("Recherchez un identifiant ou ajoutez votre premier mot de passe.", 12, "#91A4C1"); status.Margin = new Thickness(0, 18, 0, 0); Grid.SetRow(status, 3); main.Children.Add(status);
            Content = root; Refresh();
        }
        void Refresh() {
            if (list == null || !vault.IsOpen) return;
            string previous = selected == null ? null : selected.Id;
            string query = search.Text.Trim(); list.Items.Clear();
            var entries = vault.Entries.Where(e => (categoryFilter ? e.Category == filter : filter == "Tous" || e.Favorite) && (e.Name + " " + e.Username + " " + e.Url + " " + CategoryLabel(e.Category)).IndexOf(query, StringComparison.OrdinalIgnoreCase) >= 0).OrderByDescending(e => e.Favorite).ThenBy(e => e.Name).ToList();
            count.Text = entries.Count + " identifiant" + (entries.Count == 1 ? "" : "s") + "  /  " + (categoryFilter ? CategoryLabel(filter) : filter);
            foreach (var entry in entries) {
                var panel = new StackPanel(); panel.Children.Add(Text((entry.Favorite ? "★  " : "") + entry.Name, 16)); panel.Children.Add(Text(String.IsNullOrEmpty(entry.Username) ? CategoryLabel(entry.Category) : entry.Username, 12, "#9FB2D0"));
                var item = new ListBoxItem { Content = panel, Tag = entry }; list.Items.Add(item); if (entry.Id == previous) list.SelectedItem = item;
            }
            if (list.SelectedIndex < 0 && list.Items.Count > 0) list.SelectedIndex = 0;
            if (entries.Count == 0) { selected = null; ShowDetails(); }
        }
        void ShowDetails() {
            if (details == null) return;
            details.Children.Clear(); secretLabel = null;
            if (selected == null) {
                details.Children.Add(Text("◇", 64, "#83ABFF")); details.Children.Add(Text(vault.Entries.Count == 0 ? "Tout commence ici." : "Aucun résultat.", 25));
                details.Children.Add(Text(vault.Entries.Count == 0 ? "Enregistrez votre premier identifiant. Donnez-lui un nom, ajoutez son mot de passe et retrouvez-le ici à tout moment." : "Essayez une autre recherche ou une autre catégorie.", 14, "#A5B5CF"));
                details.Children.Add(Button("＋  Ajouter un identifiant", delegate { Edit(null); }, true)); return;
            }
            details.Children.Add(Text(CategoryLabel(selected.Category).ToUpperInvariant(), 11, "#86ABFF")); details.Children.Add(Text(selected.Name, 28));
            details.Children.Add(Text("IDENTIFIANT", 10, "#94A5BF")); details.Children.Add(Text(String.IsNullOrEmpty(selected.Username) ? "Non renseigné" : selected.Username, 15));
            if (!String.IsNullOrEmpty(selected.Username)) details.Children.Add(Button("Copier l’identifiant", delegate { Copy(selected.Username); }));
            details.Children.Add(Text("MOT DE PASSE", 10, "#94A5BF")); secretLabel = Text("••••••••••••••••", 22); secretLabel.FontFamily = new FontFamily("Consolas"); details.Children.Add(secretLabel);
            var actions = new WrapPanel(); actions.Children.Add(Button("Copier", delegate { Copy(selected.Password); }, true)); actions.Children.Add(Button("Afficher / masquer", delegate { if (secretLabel.Text == "••••••••••••••••") { secretLabel.Text = selected.Password; revealUntil = DateTime.UtcNow.AddSeconds(10); } else HideSecret(); })); details.Children.Add(actions);
            details.Children.Add(Text("Affichage limité à 10 secondes.", 11, "#91A4C1"));
            if (selected.Url.Length > 0) { details.Children.Add(Text("SITE / APPLICATION", 10, "#94A5BF")); details.Children.Add(Text(selected.Url, 14)); }
            if (selected.Notes.Length > 0) { details.Children.Add(Text("NOTES", 10, "#94A5BF")); details.Children.Add(Text(selected.Notes, 14)); }
            DateTime date; if (DateTime.TryParse(selected.Updated, out date)) details.Children.Add(Text("Modifié le " + date.ToLocalTime().ToString("dd/MM/yyyy à HH:mm"), 11, "#94A5BF"));
            var footer = new WrapPanel(); footer.Children.Add(Button("Modifier", delegate { Edit(selected); })); footer.Children.Add(Button(selected.Favorite ? "★  Retirer" : "☆  Favori", ToggleFavorite)); footer.Children.Add(Button("Supprimer", Delete)); details.Children.Add(footer);
        }
        void HideSecret() { if (secretLabel != null) secretLabel.Text = "••••••••••••••••"; }
        void Copy(string value) {
            try {
                var data = new DataObject(); data.SetData(DataFormats.UnicodeText, value);
                data.SetData("CanIncludeInClipboardHistory", new MemoryStream(BitConverter.GetBytes(0)));
                data.SetData("CanUploadToCloudClipboard", new MemoryStream(BitConverter.GetBytes(0)));
                data.SetData("ExcludeClipboardContentFromMonitorProcessing", new MemoryStream(new byte[] { 0 }));
                Clipboard.SetDataObject(data, true); copied = value; copiedAt = DateTime.UtcNow;
                if (status != null) status.Text = "Copié. Le presse-papiers sera effacé dans 20 secondes.";
            } catch { MessageBox.Show(modal ?? this, "Le presse-papiers est occupé. Réessayez.", "CompanionPasswords"); }
        }
        void ClearClipboard() {
            if (copied == null) return;
            try { if (Clipboard.ContainsText() && Clipboard.GetText() == copied) Clipboard.Clear(); copied = null; }
            catch { /* Keep the pending cleanup for the next timer tick. */ }
        }
        void Lock() {
            ClearClipboard(); HideSecret();
            if (busy) { pendingLock = true; if (Content is UIElement) ((UIElement)Content).Visibility = Visibility.Hidden; if (modal != null && modal.Content is UIElement) ((UIElement)modal.Content).Visibility = Visibility.Hidden; return; }
            if (modal != null) modal.Close(); ClearClipboard(); HideSecret(); vault.Lock(); selected = null;
            if (details != null) details.Children.Clear(); if (list != null) list.Items.Clear();
            details = null; list = null; search = null; secretLabel = null; status = null; filter = "Tous"; categoryFilter = false;
            ShowLogin();
        }
        Window Dialog(string title, double width = 520) {
            var w = new Window { Title = title, Width = width, SizeToContent = SizeToContent.Height, MaxHeight = Math.Max(500, SystemParameters.WorkArea.Height - 70), WindowStartupLocation = WindowStartupLocation.CenterOwner, Owner = this, ResizeMode = ResizeMode.NoResize };
            w.PreviewKeyDown += delegate(object s, KeyEventArgs e) { activity = DateTime.UtcNow; if (e.Key == Key.Escape && !busy) w.Close(); if (e.Key == Key.L && (Keyboard.Modifiers & ModifierKeys.Control) != 0) Lock(); };
            w.PreviewMouseDown += delegate { activity = DateTime.UtcNow; };
            w.Closing += delegate(object s, System.ComponentModel.CancelEventArgs e) { if (busy) e.Cancel = true; };
            w.SourceInitialized += delegate { if (!smoke) SetWindowDisplayAffinity(new WindowInteropHelper(w).Handle, 0x11); };
            return w;
        }
        void ShowModal(Window window) { modal = window; try { window.ShowDialog(); } finally { modal = null; activity = DateTime.UtcNow; } }
        void Edit(Entry original) {
            var w = Dialog(original == null ? "Ajouter un identifiant" : "Modifier l’identifiant", 570); var panel = new StackPanel { Margin = new Thickness(28) };
            panel.Children.Add(Text(original == null ? "Un nouvel identifiant" : "Modifier l’identifiant", 25));
            var name = Field(panel, "Nom du site, de l’application ou du service *", original == null ? "" : original.Name); name.MaxLength = 200;
            var password = Secret(panel, "Mot de passe *"); password.Password = original == null ? "" : original.Password;
            panel.Children.Add(Button("↻  Générer un mot de passe de 24 caractères", delegate { password.Password = Vault.Generate(24); }));
            var username = Field(panel, "Identifiant / e-mail (facultatif)", original == null ? "" : original.Username);
            var url = Field(panel, "Adresse du site (facultatif)", original == null ? "" : original.Url);
            panel.Children.Add(Text("Catégorie", 12, "#A9B8D0"));
            var categories = new ComboBox { Name = "EntryCategory", Margin = new Thickness(0, 6, 0, 16), Padding = new Thickness(12), Foreground = Brush("#0B1220"), MaxDropDownHeight = 240 };
            string initialCategory = original != null ? original.Category : categoryFilter ? filter : vault.Categories.FirstOrDefault() ?? "";
            foreach (var cat in vault.Categories.Concat(new[] { "" })) { var item = new ComboBoxItem { Content = CategoryLabel(cat), Tag = cat }; categories.Items.Add(item); if (cat == initialCategory) categories.SelectedItem = item; }
            if (categories.SelectedIndex < 0) categories.SelectedIndex = categories.Items.Count - 1;
            panel.Children.Add(categories);
            var notes = Field(panel, "Notes (facultatif)", original == null ? "" : original.Notes); notes.AcceptsReturn = true; notes.Height = 74; notes.VerticalScrollBarVisibility = ScrollBarVisibility.Auto;
            var favorite = new CheckBox { Content = "Ajouter aux favoris", IsChecked = original != null && original.Favorite }; panel.Children.Add(favorite);
            var feedback = Text("", 12, "#FFA8AB"); panel.Children.Add(feedback);
            var buttons = new WrapPanel(); buttons.Children.Add(Button("Enregistrer", delegate {
                if (!vault.IsOpen) { w.Close(); return; }
                if (String.IsNullOrWhiteSpace(name.Text) || password.Password.Length == 0) { feedback.Text = "Le nom et le mot de passe sont obligatoires."; return; }
                var entry = original == null ? new Entry() : original.Copy(); entry.Name = name.Text.Trim(); entry.Password = password.Password; entry.Username = username.Text.Trim(); entry.Url = url.Text.Trim(); entry.Notes = notes.Text; entry.Category = (string)((ComboBoxItem)categories.SelectedItem).Tag; entry.Favorite = favorite.IsChecked == true; entry.Updated = DateTime.UtcNow.ToString("o");
                try { var items = vault.Entries.Where(e => e.Id != entry.Id).ToList(); items.Add(entry); vault.Save(items); selected = entry; Refresh(); w.Close(); status.Text = "Identifiant enregistré dans le coffre chiffré."; } catch (Exception ex) { Error(ex); }
            }, true)); buttons.Children.Add(Button("Annuler", delegate { w.Close(); })); panel.Children.Add(buttons);
            w.Content = new ScrollViewer { Content = panel, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
            w.Closed += delegate { password.Clear(); name.Clear(); username.Clear(); url.Clear(); notes.Clear(); };
            ShowModal(w);
        }
        static string CategoryLabel(string name) { return name.Length == 0 ? "Sans catégorie" : name; }
        void ManageCategories() {
            if (!vault.IsOpen) return;
            var w = Dialog("Gérer les catégories", 560);
            var panel = new StackPanel { Margin = new Thickness(28) };
            panel.Children.Add(Text("Vos catégories", 26));
            panel.Children.Add(Text("Créez une catégorie, ou sélectionnez-en une pour la renommer ou la supprimer.", 14, "#A5B5CF"));
            var categories = new ListBox { Name = "CategoryList", Height = 210 }; panel.Children.Add(categories);
            var name = Field(panel, "Nom de la catégorie"); name.MaxLength = 80;
            var feedback = Text("", 12, "#FFA8AB");
            Action<string> reload = delegate(string chosen) {
                categories.Items.Clear();
                foreach (var c in vault.Categories) {
                    int total = vault.Entries.Count(e => e.Category == c);
                    var item = new ListBoxItem { Content = Text(c + "  ·  " + total + " identifiant(s)", 14), Tag = c };
                    categories.Items.Add(item); if (c == chosen) categories.SelectedItem = item;
                }
            };
            categories.SelectionChanged += delegate { var item = categories.SelectedItem as ListBoxItem; if (item != null) name.Text = (string)item.Tag; feedback.Text = ""; };
            Action refreshVault = delegate {
                string query = search.Text; var previous = selected;
                ShowVault(); search.Text = query;
                selected = previous == null ? null : vault.Entries.FirstOrDefault(e => e.Id == previous.Id); Refresh();
            };
            var actions = new WrapPanel();
            actions.Children.Add(Button("Créer", delegate {
                try { string next = name.Text.Trim(); vault.AddCategory(next); reload(next); refreshVault(); feedback.Text = "Catégorie créée."; }
                catch (Exception ex) { feedback.Text = ex.Message; }
            }, true));
            var rename = Button("Renommer", delegate {
                var item = categories.SelectedItem as ListBoxItem; if (item == null) return;
                try { string previous = (string)item.Tag, next = name.Text.Trim(); vault.RenameCategory(previous, next); if (categoryFilter && filter == previous) filter = next; reload(next); refreshVault(); feedback.Text = "Catégorie renommée, identifiants mis à jour."; }
                catch (Exception ex) { feedback.Text = ex.Message; }
            }); actions.Children.Add(rename);
            var delete = Button("Supprimer", delegate {
                var item = categories.SelectedItem as ListBoxItem; if (item == null) return;
                string previous = (string)item.Tag;
                if (MessageBox.Show(w, "Supprimer la catégorie « " + previous + " » ?\n\nSes identifiants seront conservés dans « Sans catégorie ».", "Supprimer une catégorie", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes || !vault.IsOpen) return;
                try { vault.DeleteCategory(previous); if (categoryFilter && filter == previous) filter = ""; reload(null); name.Clear(); refreshVault(); feedback.Text = "Catégorie supprimée. Les identifiants sont conservés."; }
                catch (Exception ex) { feedback.Text = ex.Message; }
            }); actions.Children.Add(delete);
            Action selectionChanged = delegate { rename.IsEnabled = delete.IsEnabled = categories.SelectedItem != null; };
            categories.SelectionChanged += delegate { selectionChanged(); };
            panel.Children.Add(actions); panel.Children.Add(feedback);
            panel.Children.Add(Text("Les catégories sont chiffrées avec le coffre. Supprimer une catégorie ne supprime jamais ses mots de passe.", 12, "#A5B5CF"));
            panel.Children.Add(Button("Fermer", delegate { w.Close(); }));
            reload(null); selectionChanged();
            w.Content = new ScrollViewer { Content = panel, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
            w.Closed += delegate { name.Clear(); categories.Items.Clear(); };
            ShowModal(w);
        }
        void ToggleFavorite() { if (selected == null) return; try { var replacement = selected.Copy(); replacement.Favorite = !replacement.Favorite; vault.Save(vault.Entries.Select(e => e.Id == replacement.Id ? replacement : e).ToList()); Refresh(); } catch (Exception ex) { Error(ex); } }
        void Delete() {
            if (selected == null) return; string id = selected.Id;
            if (MessageBox.Show(this, "Supprimer cet identifiant du coffre ?", "Supprimer", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes || !vault.IsOpen) return;
            try { vault.Save(vault.Entries.Where(e => e.Id != id).ToList()); Refresh(); status.Text = "Identifiant supprimé. Les anciennes sauvegardes peuvent encore le contenir."; } catch (Exception ex) { Error(ex); }
        }
        void Generator() {
            var w = Dialog("Générateur de mots de passe"); var p = new StackPanel { Margin = new Thickness(28) }; p.Children.Add(Text("Unique. Aléatoire. À vous.", 25)); p.Children.Add(Text("Lettres, chiffres et symboles. Utilisez un mot de passe différent pour chaque compte.", 14, "#A5B5CF"));
            var label = Text("24 caractères", 14); p.Children.Add(label); var slider = new Slider { Minimum = 16, Maximum = 64, Value = 24, TickFrequency = 1, IsSnapToTickEnabled = true, Margin = new Thickness(0, 8, 0, 18) }; p.Children.Add(slider);
            var output = Field(p, "Mot de passe généré", Vault.Generate(24)); output.IsReadOnly = true; output.FontFamily = new FontFamily("Consolas"); output.TextWrapping = TextWrapping.Wrap;
            slider.ValueChanged += delegate { label.Text = ((int)slider.Value) + " caractères"; output.Text = Vault.Generate((int)slider.Value); };
            p.Children.Add(Button("↻  Générer à nouveau", delegate { output.Text = Vault.Generate((int)slider.Value); })); p.Children.Add(Button("Copier pendant 20 secondes", delegate { Copy(output.Text); }, true));
            w.Content = p; w.Closed += delegate { output.Clear(); }; ShowModal(w);
        }
        void Export() {
            var dialog = new SaveFileDialog { Filter = "Coffre chiffré CompanionPasswords|*.cpvault", FileName = "CompanionPasswords-" + DateTime.Now.ToString("yyyy-MM-dd-HHmmss") + ".cpvault" };
            if (dialog.ShowDialog(this) != true || !vault.IsOpen) return;
            try { vault.Export(dialog.FileName); status.Text = "Sauvegarde chiffrée créée. Conservez une copie sur un support déconnecté."; } catch (Exception ex) { Error(ex); }
        }
        void Restore() {
            if (busy) return;
            var dialog = new OpenFileDialog { Filter = "Coffre chiffré|*.cpvault;*.bak|Tous les fichiers|*.*" };
            if (dialog.ShowDialog(this) != true) return;
            string source = dialog.FileName;
            if (String.Equals(System.IO.Path.GetFullPath(source), System.IO.Path.GetFullPath(vault.Path), StringComparison.OrdinalIgnoreCase)) { MessageBox.Show(this, "Ce fichier est déjà votre coffre actuel."); return; }
            var w = Dialog("Restaurer un coffre"); var p = new StackPanel { Margin = new Thickness(28) }; p.Children.Add(Text("Restaurer votre sauvegarde", 24)); p.Children.Add(Text("Le coffre actuel sera remplacé après vérification. Une copie chiffrée de l’ancien coffre sera conservée dans le dossier local. Les identifiants ne sont pas fusionnés.", 14, "#A5B5CF"));
            var password = Secret(p, "Mot de passe principal de la sauvegarde"); var feedback = Text("", 12, "#FFA8AB"); p.Children.Add(feedback);
            var restore = Button("Vérifier et restaurer", delegate { }, true); restore.Click += async delegate {
                if (busy) return; if (DateTime.UtcNow < retryAt) { feedback.Text = "Patientez quelques secondes avant de réessayer."; return; }
                string master = password.Password; password.Clear(); busy = true; restore.IsEnabled = false;
                feedback.Text = "Vérification de la sauvegarde…";
                try {
                    // Work on an immutable snapshot, never re-read a mutable source after verification.
                    byte[] snapshot = Vault.Read(source);
                    string temp = System.IO.Path.Combine(System.IO.Path.GetDirectoryName(vault.Path), ".restore-" + Guid.NewGuid().ToString("N"));
                    try {
                        Vault.AtomicWrite(temp, snapshot, null);
                        await Task.Run(delegate { using (var probe = new Vault(temp)) probe.Unlock(master); });
                        if (File.Exists(vault.Path)) Vault.AtomicWrite(vault.Path + ".before-restore-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".cpvault", Vault.ReadRaw(vault.Path), null);
                        Vault.AtomicWrite(vault.Path, snapshot, vault.Path + ".bak");
                    } finally { if (File.Exists(temp)) File.Delete(temp); }
                    busy = false; w.Close(); ShowLogin(); MessageBox.Show(this, "Sauvegarde restaurée. Déverrouillez-la avec son mot de passe principal.", "CompanionPasswords");
                } catch (Exception ex) { failures++; retryAt = DateTime.UtcNow.AddSeconds(Math.Min(30, failures * 2)); feedback.Text = ex is CryptographicException ? "Mot de passe incorrect ou coffre endommagé." : "Restauration impossible : " + ex.Message; }
                finally { master = null; busy = false; restore.IsEnabled = true; if (pendingLock) { pendingLock = false; Lock(); } }
            }; p.Children.Add(restore); w.Content = p; w.Closed += delegate { password.Clear(); }; ShowModal(w);
        }
        void Security() {
            var w = Dialog("Sécurité du coffre", 580); var p = new StackPanel { Margin = new Thickness(28) };
            p.Children.Add(Text("Votre sécurité, en clair.", 26));
            p.Children.Add(Text("●  AES-256 + contrôle d’intégrité HMAC-SHA256\n●  Mot de passe principal : PBKDF2, 600 000 itérations\n●  Verrouillage après 2 min, réduction et verrouillage Windows\n●  Aucun serveur, aucune télémétrie", 14, "#85DEBF"));
            p.Children.Add(Text("Un PC infecté peut capturer vos frappes ou lire la mémoire lorsque le coffre est ouvert. Cette application ne remplace pas un antivirus. Les sauvegardes locales peuvent être supprimées ou chiffrées par un ransomware : gardez aussi une copie déconnectée.", 13, "#B6C4DA"));
            p.Children.Add(Text("Dossier du coffre", 12, "#86ABFF")); p.Children.Add(Text(System.IO.Path.GetDirectoryName(vault.Path), 12, "#A5B5CF"));
            p.Children.Add(Button("Changer le mot de passe principal", delegate { w.Close(); Dispatcher.BeginInvoke(new Action(ChangeMaster)); }));
            p.Children.Add(Text("Les captures sont bloquées sur les versions compatibles de Windows. Les copies demandent l’exclusion de l’historique Windows ; un gestionnaire tiers peut toutefois les conserver. Aucun audit de sécurité indépendant n’a été réalisé.", 12, "#94A5BF"));
            w.Content = p; ShowModal(w);
        }
        void ChangeMaster() {
            if (!vault.IsOpen) return;
            var w = Dialog("Changer le mot de passe principal"); var p = new StackPanel { Margin = new Thickness(28) }; p.Children.Add(Text("Une nouvelle clé pour le coffre", 23));
            var current = Secret(p, "Mot de passe principal actuel"); var password = Secret(p, "Nouveau mot de passe (14 caractères minimum)"); var confirm = Secret(p, "Confirmer le nouveau mot de passe");
            p.Children.Add(Text("Les anciennes sauvegardes, dont la copie automatique .bak, conservent leur ancien mot de passe. Créez une nouvelle sauvegarde après ce changement.", 12, "#A5B5CF")); var feedback = Text("", 12, "#FFA8AB"); p.Children.Add(feedback);
            var save = Button("Changer le mot de passe", delegate { }, true); save.Click += async delegate {
                if (busy) return;
                if (DateTime.UtcNow < retryAt) { feedback.Text = "Patientez quelques secondes avant de réessayer."; return; }
                if (password.Password != confirm.Password) { feedback.Text = "Les nouveaux mots de passe ne correspondent pas."; return; }
                try { Vault.ValidateMaster(password.Password); } catch (Exception ex) { feedback.Text = ex.Message; return; }
                string old = current.Password, next = password.Password; current.Clear(); password.Clear(); confirm.Clear(); busy = true; save.IsEnabled = false; feedback.Text = "Modification sécurisée en cours…";
                try {
                    await Task.Run(delegate { using (var probe = new Vault(vault.Path)) probe.Unlock(old); vault.ChangeMaster(next); });
                    busy = false; w.Close(); status.Text = "Mot de passe principal modifié. Créez une nouvelle sauvegarde.";
                } catch (Exception ex) { failures++; retryAt = DateTime.UtcNow.AddSeconds(Math.Min(30, failures * 2)); feedback.Text = ex is CryptographicException ? "Mot de passe actuel incorrect ou coffre endommagé." : ex.Message; }
                finally { old = null; next = null; busy = false; save.IsEnabled = true; if (pendingLock) { pendingLock = false; Lock(); } }
            }; p.Children.Add(save); w.Content = p; w.Closed += delegate { current.Clear(); password.Clear(); confirm.Clear(); }; ShowModal(w);
        }
        // Queue dialog interactions before entering ShowDialog's nested dispatcher loop.
        #pragma warning disable 4014
        async Task Smoke() {
            try {
                Directory.CreateDirectory("artifacts"); Snapshot("artifacts/login.png");
                await Task.Run(delegate { vault.Create("Demo-only-phrase-2026!"); });
                vault.Save(new List<Entry> { new Entry { Name = "Instagram", Username = "camille.exemple", Password = "Fictif-uniquement!123", Category = "Personnel", Favorite = true }, new Entry { Name = "Notion", Username = "camille@example.test", Password = "Demo-12345!67890", Category = "Travail", Notes = "Espace de travail personnel" }, new Entry { Name = "Steam", Password = "Fictif-123456789!", Category = "Personnel" } });
                ShowVault(); UpdateLayout(); Snapshot("artifacts/coffre.png");
                search.Text = "notion"; if (list.Items.Count != 1) throw new Exception("Search failed");
                filter = "Favoris"; search.Text = ""; Refresh(); if (list.Items.Count != 1) throw new Exception("Favorites failed");
                Exception dialogFailure = null;
                Dispatcher.BeginInvoke(DispatcherPriority.ApplicationIdle, new Action(delegate {
                    try {
                        var name = Descendants<TextBox>(modal).First();
                        name.Text = "Jeux";
                        Descendants<Button>(modal).First(b => (string)b.Content == "Créer").RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Button.ClickEvent));
                        if (!vault.Categories.Contains("Jeux")) throw new Exception("Category creation UI failed");
                        name.Text = "Jeux vidéo";
                        Descendants<Button>(modal).First(b => (string)b.Content == "Renommer").RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Button.ClickEvent));
                        if (!vault.Categories.Contains("Jeux vidéo") || vault.Categories.Contains("Jeux")) throw new Exception("Category rename UI failed");
                        var choices = Descendants<ListBox>(modal).First();
                        choices.SelectedItem = choices.Items.Cast<ListBoxItem>().First(i => (string)i.Tag == "Personnel");
                        name.Text = "Vie privée";
                        Descendants<Button>(modal).First(b => (string)b.Content == "Renommer").RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Button.ClickEvent));
                        if (vault.Entries.First(e => e.Name == "Instagram").Category != "Vie privée") throw new Exception("Category rename did not propagate");
                        Snapshot("artifacts/categories.png", modal);
                        modal.Close();
                    } catch (Exception ex) { dialogFailure = ex; if (modal != null) modal.Close(); }
                }));
                ManageCategories(); if (dialogFailure != null) throw dialogFailure;
                Dispatcher.BeginInvoke(DispatcherPriority.ApplicationIdle, new Action(delegate {
                    try {
                        var fields = Descendants<TextBox>(modal).ToList(); var passwords = Descendants<PasswordBox>(modal).ToList();
                        var save = Descendants<Button>(modal).First(b => (string)b.Content == "Enregistrer");
                        save.RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Button.ClickEvent));
                        if (!modal.IsVisible) throw new Exception("Empty form should stay open");
                        fields[0].Text = "Compte de test UI"; passwords[0].Password = "Mot-de-passe-fictif!123"; fields[1].Text = "demo@example.test";
                        var category = Descendants<ComboBox>(modal).First(); category.SelectedItem = category.Items.Cast<ComboBoxItem>().First(i => (string)i.Tag == "Jeux vidéo");
                        save.RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Button.ClickEvent));
                    } catch (Exception ex) { dialogFailure = ex; if (modal != null) modal.Close(); }
                }));
                Edit(null); if (dialogFailure != null) throw dialogFailure;
                var added = vault.Entries.Single(e => e.Name == "Compte de test UI");
                if (added.Password != "Mot-de-passe-fictif!123") throw new Exception("Dialog save failed");
                if (added.Category != "Jeux vidéo") throw new Exception("Category chooser failed");
                filter = "Jeux vidéo"; categoryFilter = true; Refresh(); if (list.Items.Count != 1) throw new Exception("Custom category filter failed");
                Dispatcher.BeginInvoke(DispatcherPriority.ApplicationIdle, new Action(delegate {
                    try {
                        Descendants<TextBox>(modal).First().Text = "Compte modifié UI";
                        var category = Descendants<ComboBox>(modal).First(); category.SelectedItem = category.Items.Cast<ComboBoxItem>().First(i => (string)i.Tag == "");
                        Descendants<Button>(modal).First(b => (string)b.Content == "Enregistrer").RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Button.ClickEvent));
                    } catch (Exception ex) { dialogFailure = ex; if (modal != null) modal.Close(); }
                }));
                Edit(added); if (dialogFailure != null) throw dialogFailure;
                if (!vault.Entries.Any(e => e.Name == "Compte modifié UI")) throw new Exception("Dialog edit failed");
                if (vault.Entries.Single(e => e.Id == added.Id).Category != "") throw new Exception("Category reassignment failed");
                filter = ""; categoryFilter = true; Refresh(); if (list.Items.Count != 1) throw new Exception("Uncategorized filter failed");
                vault.AddCategory("Tous"); filter = "Tous"; categoryFilter = true; Refresh(); if (list.Items.Count != 0) throw new Exception("Category name collides with all filter");
                Lock(); if (vault.IsOpen || list != null || selected != null) throw new Exception("Lock failed");
                File.WriteAllText("artifacts/ui-tests.txt", "PASS: startup, search, favorites, category manager create/rename, entry category chooser/reassignment, custom/uncategorized filters, reserved-filter name collision, entry validation/add/edit, lock.\r\n");
            } catch (Exception ex) { File.WriteAllText("artifacts/ui-tests.txt", "FAIL: " + ex); }
            Close();
        }
        #pragma warning restore 4014
        static IEnumerable<T> Descendants<T>(DependencyObject root) where T : DependencyObject {
            foreach (object child in LogicalTreeHelper.GetChildren(root)) {
                var node = child as DependencyObject; if (node == null) continue;
                if (node is T) yield return (T)node;
                foreach (var descendant in Descendants<T>(node)) yield return descendant;
            }
        }
        void Snapshot(string path, Window target = null) {
            target = target ?? this;
            target.UpdateLayout(); var bitmap = new RenderTargetBitmap((int)target.ActualWidth, (int)target.ActualHeight, 96, 96, PixelFormats.Pbgra32); bitmap.Render(target);
            var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap)); using (var file = File.Create(path)) encoder.Save(file);
        }
    }
}
