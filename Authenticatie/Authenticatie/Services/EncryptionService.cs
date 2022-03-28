using Authenticatie.Models;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace Authenticatie.Services
{
    public interface IEncryption
    {
        public string CreateToken(Bericht bericht);
        public void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt);
        public void CreateBerichtHash(string bericht, out byte[] berichtHash, out byte[] berichtSalt);
    }
    // is de interface dit wou zeggen dat men dit overal in elke applicatie kan gebruiken as men EncriptionService definieert.

    public class EncryptionService : IEncryption
    {
        private readonly IConfiguration _configuration;

        public EncryptionService(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        //?
        public string CreateToken(Bericht bericht)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, bericht.BerichtInfo)
            };

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(
                _configuration.GetSection("AppSettings:Token").Value));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: creds);

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }

        public void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key; //public key
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password)); //gaat wachtwoord hashen
            }
        }
        public void CreateBerichtHash(string bericht, out byte[] berichtHash, out byte[] berichtSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                berichtSalt = hmac.Key; //public key
                berichtHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(bericht)); //gaat wachtwoord hashen
            }
        }
    }
}
