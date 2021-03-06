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


        [HttpPost("register")] //registreert persoon en hashed het wachtwoord
        public async Task<ActionResult<Bericht>> Register(BerichtDto request)
        {
            if (request.WantPassword == true)
            {
                _encryptionService.CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt); // gaat het wachtwoord opvragen dat in gegeven is.
                bericht.BerichtInfo = request.BerichtInfo; //gaat het bericht opvragen dat ingegeven is.
                bericht.PasswordHash = passwordHash;
                bericht.PasswordSalt = passwordSalt;

                return Ok(bericht);
            }

        }

        [HttpPost("Login")]// login zoekt op naam 
        public async Task<ActionResult<string>> Login(BerichtDto request)
        {
            if (bericht.BerichtInfo != request.BerichtInfo)
            {
                return BadRequest("User Not found.");
            }
            if (!VerifyPasswordHash(request.Password, bericht.PasswordHash, bericht.PasswordSalt))
            {
                return BadRequest("Password is wrong");
            }

            string token = _encryptionService.CreateToken(bericht);
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
