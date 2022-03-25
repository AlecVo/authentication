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
       
        private IEncryption _encryptionService;

        public AuthController(IEncryption encryptionService)
        {
            _encryptionService = encryptionService;

        }


        [HttpPost("Aanmaken Bericht")] //Maakt een bericht aan en hashed het.
        public async Task<ActionResult<Bericht>> AanmakenBericht(BerichtDto request)
        {
            _encryptionService.CreatePasswordHash(request.wachtwoord, out byte[] passwordHash, out byte[] passwordSalt);
            Bericht bericht = new Bericht();
            bericht.BerichtInhoud = request.berichtInhoud;
            bericht.WachtwoordHash = passwordHash;
            bericht.WachtwoordSalt = passwordSalt;

            return Ok(bericht);
        }

        [HttpPost("Login")]// login zoekt op naam 
        public async Task<ActionResult<string>> Login(BerichtDto request)
        {
            if (user.UserName != request.UserName)
            {
                return BadRequest("User Not found.");
            }
            if (!VerifyPasswordHash(request.wachtwoord, user.PasswordHash, user.PasswordSalt))
            {
                return BadRequest("Password is wrong");
            }

            string token = _encryptionService.CreateToken(user);
            return Ok(token);
        }


        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using(var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash); //SequenceEqual is letterlijk hetzelfde als ==, als het gehashed wachtwoord het zelfde is als het opgeslagen wachtwoord return true ander is het false
            }
        }
    }
}
