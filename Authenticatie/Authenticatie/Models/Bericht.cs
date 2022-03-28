namespace Authenticatie.Models
{
    public class Bericht
    {
        public string BerichtInfo { get; set; } = string.Empty;
        public byte[] PasswordHash { get; set; }
        public byte[] PasswordSalt { get; set; }
        public byte[] BerichtHash { get; set; }
        public byte[] BerichtSalt { get; set; }
        public string PublicKey { get; set; }
    }
}
