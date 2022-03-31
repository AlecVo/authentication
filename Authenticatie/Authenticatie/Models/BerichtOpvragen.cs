using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Authenticatie.Models
{
    public class BerichtOpvragen
    {
        public string Password { get; set; } = string.Empty;
        public byte[] PasswordSalt { get; set; }
        public bool WantPassword { get; set; }
    }
}
