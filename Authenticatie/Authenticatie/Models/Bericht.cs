namespace Authenticatie.Models
{
    public class Bericht
    {
        public string BerichtInfo { get; set; } = string.Empty;
        public byte[] PasswordHash { get; set; }
        public byte[] PasswordSalt { get; set; }
    }
}
