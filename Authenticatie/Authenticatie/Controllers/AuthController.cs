using Authenticatie.Models;
using Authenticatie.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace Authenticatie.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static Bericht bericht = new Bericht();
        private IEncryption _encryptionService;

        public AuthController(IEncryption encryptionService)
        {
            _encryptionService = encryptionService;

        }


        [HttpPost("Aanmaken Bericht")] //Maakt een bericht aan en hashed het.
        public async Task<ActionResult<Bericht>> AanmakenBericht(BerichtDto request)
        {
            _encryptionService.CreatePasswordHash(out byte[] passwordHash, out byte[] passwordSalt);
            
            bericht.BerichtInhoud = request.berichtInhoud;
            bericht.WachtwoordHash = passwordHash;
            bericht.WachtwoordSalt = passwordSalt;

            return Ok(bericht);
        }

        [HttpPost("Login")]// login zoekt op naam 
        public async Task<ActionResult<string>> Login(BerichtDto request)
        {
            if (bericht.BerichtInhoud != request.berichtInhoud)
            {
                return BadRequest("User Not found.");
            }
            if (!VerifyPasswordHash( bericht.WachtwoordHash, bericht.WachtwoordSalt))
            {
                return BadRequest("Password is wrong");
            }

            string token = _encryptionService.CreateToken(bericht);
            return Ok(token);
        }


        private bool VerifyPasswordHash(byte[] passwordHash, byte[] passwordSalt)
        {
            using(var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(bericht));
                return computedHash.SequenceEqual(passwordHash); //SequenceEqual is letterlijk hetzelfde als ==, als het gehashed wachtwoord het zelfde is als het opgeslagen wachtwoord return true ander is het false
            }
        }
    }
}
