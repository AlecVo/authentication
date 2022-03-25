namespace Authenticatie.Models
{
    public class Bericht
    {
        public string BerichtInhoud { get; set; } = string.Empty;
        public byte[] WachtwoordHash { get; set; }
        public byte[] WachtwoordSalt { get; set; }
    }
}
