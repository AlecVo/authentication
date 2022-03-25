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


        [HttpPost("register")] //registreert persoon en hashed het wachtwoord
        public async Task<ActionResult<User>> Register(UserDto request)
        {
            _encryptionService.CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);
            User user = new User();
            user.UserName = request.UserName;
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;

            return Ok(user);
        }

        [HttpPost("Login")]// login zoekt op naam 
        public async Task<ActionResult<string>> Login(UserDto request)
        {
            if (user.UserName != request.UserName)
            {
                return BadRequest("User Not found.");
            }
            if (!VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt))
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
