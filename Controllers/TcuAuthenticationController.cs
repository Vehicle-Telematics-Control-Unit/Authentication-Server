using AuthenticationServer.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace AuthenticationServer.Controllers
{
    [Route("api/TCU")]
    [ApiController]
    public class TCUAuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> userManager;
        private readonly TcuContext tcuContext;
        private readonly IConfiguration _config;

        public TCUAuthenticationController(TcuContext tcuContext, UserManager<IdentityUser> userManager, IConfiguration config) //RoleManager<IdentityRole> roleManager, IConfiguration config)
        {
            this.userManager = userManager;
            this.tcuContext = tcuContext;
            _config = config;
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login(string VIN, string Cipher)
        {
            var vehicle = (from _vehicle in tcuContext.Tcus
                           where _vehicle.Vin == VIN
                           select _vehicle).FirstOrDefault();

            if (vehicle == null)
                return NotFound();

            var user = await userManager.FindByIdAsync(vehicle.UserId);

            Aes decryptor = Aes.Create();

            decryptor.IV = Encoding.Unicode.GetBytes(user.PasswordHash);

            decryptor.Key = Encoding.Unicode.GetBytes(_config.GetValue<string>("TcuSecretKey"));

            var password = "";

            using (MemoryStream memoryStream = new(Encoding.Unicode.GetBytes(Cipher)))
            {
                using CryptoStream cryptoStream =
                   new(memoryStream, decryptor.CreateDecryptor(), CryptoStreamMode.Read);
                byte[] decryptedBytes = new byte[Cipher.Length];
                cryptoStream.Read(decryptedBytes, 0, decryptedBytes.Length);
                password = Encoding.Unicode.GetString(decryptedBytes).Replace("\0", "");
            }

            if (await userManager.CheckPasswordAsync(user, password))
            {

                #pragma warning disable CS8602 // Possible null reference argument.
                vehicle.IpAddress = Request.HttpContext.Connection.RemoteIpAddress.ToString();
                #pragma warning restore CS8602 // Possible null reference argument.

                await tcuContext.SaveChangesAsync();

                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, vehicle.Vin),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim("TCU", "True")
                };

                var token = GenerateJwtToken(authClaims);

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    expiration = token.ValidTo
                });
            }
            return Unauthorized();
        }

        private JwtSecurityToken GenerateJwtToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config.GetValue<string>("JWT:Secret")));
            var token = new JwtSecurityToken(
                issuer: _config["JWT:ValidIssuer"],
                audience: _config["JWT:ValidAudience"],
                expires: DateTime.Now.AddMinutes(30),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );
            return token;
        }
    }
}
