using AuthenticationServer.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using AuthenticationServer.Services;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Prng;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AuthenticationServer.Models.Commands;

namespace AuthenticationServer.Data
{
    public class BaseController : ControllerBase
    {
        protected readonly UserManager<IdentityUser> userManager;
        protected readonly TcuContext tcuContext;
        protected readonly IConfiguration _config;
        

        public BaseController(TcuContext tcuContext, UserManager<IdentityUser> userManager, IConfiguration config)
        {
            this.userManager = userManager;
            this.tcuContext = tcuContext;
            _config = config;
        }

        protected JwtSecurityToken GenerateJwtToken(List<Claim> authClaims)
        {
            if (_config["JWT:Secret"] == null)
                throw new MissingFieldException("Failed to load JWT secret key");

            string? secretKey = _config["JWT:Secret"] ?? throw new MissingFieldException("Failed to load JWT secret key");
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));

            var token = new JwtSecurityToken(
                issuer: _config["JWT:ValidIssuer"],
                audience: _config["JWT:ValidAudience"],
                expires: DateTime.Now.AddHours(3),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );
            return token;
        }


        protected async Task<IdentityUser> FindUser(string? userIdentifier)
        {
            var user = await userManager.FindByNameAsync(userIdentifier);

            user ??= await userManager.FindByEmailAsync(userIdentifier);

            return user;
        }

        protected async Task<List<Claim>> GetUserClaims(IdentityUser user)
        {
            var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

            var userRoles = await userManager.GetRolesAsync(user);

            foreach (var userRole in userRoles)
            {
                claims.Add(new Claim(ClaimTypes.Role, userRole));
            }

            return claims;
        }
    }
}
