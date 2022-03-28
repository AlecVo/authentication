namespace Authenticatie.Models
{
    public class BerichtDto
    {
        public string BerichtInfo { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public bool WantPassword { get; set; }
    }
}
