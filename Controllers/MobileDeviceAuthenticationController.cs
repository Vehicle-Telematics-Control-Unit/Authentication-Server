using AuthenticationServer.Models;
using AuthenticationServer.Models.Commands;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;

namespace AuthenticationServer.Controllers
{
    [Route("api/Mobile")]
    [ApiController]
    public class MobileDeviceAuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> userManager;
        private readonly TcuContext tcuContext;
        private readonly IConfiguration _config;

        public MobileDeviceAuthenticationController(TcuContext tcuContext, UserManager<IdentityUser> userManager, IConfiguration config) //RoleManager<IdentityRole> roleManager, IConfiguration config)
        {
            this.userManager = userManager;
            this.tcuContext = tcuContext;
            _config = config;
        }


        [HttpPost]
        [Route("login")]
      
        public async Task<IActionResult> Login([FromBody] UserCommand userCommand)
        {
            var user = await userManager.FindByNameAsync(userCommand.Username);

            user ??= await userManager.FindByEmailAsync(userCommand.Username);

            if (user == null)
                return NotFound(new JObject
                    {
                        new JProperty("error", -1)
                    });

            //if (user.EmailConfirmed == false)
            //    return NotFound(new JObject
            //        {
            //            new JProperty("error", -6)
            //        });

            if (await userManager.CheckPasswordAsync(user, userCommand.Password))
            {
                var device = (from _device in tcuContext.Devices where _device.DeviceId == userCommand.DeviceId select _device).FirstOrDefault();

                if (device == null)
                    return Unauthorized(new JObject
                    {
                        new JProperty("error", -2)
                    });
                if (device.UserId != user.Id)
                    return Unauthorized(new JObject
                    {
                        new JProperty("error", -3)
                    });

                device.LastLoginTime = DateTime.UtcNow;
                #pragma warning disable CS8602 // Possible null reference argument.
                device.IpAddress = Request.HttpContext.Connection.RemoteIpAddress.ToString();

                #pragma warning restore CS8602 // Possible null reference argument.

                await tcuContext.SaveChangesAsync();
                
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

                var userRoles = await userManager.GetRolesAsync(user);

                foreach (var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }

                authClaims.Add(new Claim("deviceId", device.DeviceId.ToString()));
                var token = GenerateJwtToken(authClaims);

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    expiration = token.ValidTo,
                    username = user.UserName,
                    email = user.Email,
                });
            }
            return Unauthorized(new JObject
                    {
                        new JProperty("error", -5)
                    });
        }

        private JwtSecurityToken GenerateJwtToken(List<Claim> authClaims)
        {
            #pragma warning disable CS8604 // Possible null reference argument.
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JWT:Secret"]));
            #pragma warning restore CS8604 // Possible null reference argument.
            var token = new JwtSecurityToken(
                issuer: _config["JWT:ValidIssuer"],
                audience: _config["JWT:ValidAudience"],
                expires: DateTime.Now.AddHours(3),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );
            return token;
        }
    }
}
