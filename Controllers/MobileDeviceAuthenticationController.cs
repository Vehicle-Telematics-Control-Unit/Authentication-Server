using AuthenticationServer.Models;
using AuthenticationServer.Models.Commands;
using AuthenticationServer.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
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
        private readonly IMailService _mailService;

        public MobileDeviceAuthenticationController(TcuContext tcuContext, UserManager<IdentityUser> userManager, IConfiguration config, IMailService mailService) //RoleManager<IdentityRole> roleManager, IConfiguration config)
        {
            this.userManager = userManager;
            this.tcuContext = tcuContext;
            _config = config;
            _mailService = mailService;
        }



        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] UserCommand userCommand)
        {
            var user = await userManager.FindByNameAsync(userCommand.Username);

            user ??= await userManager.FindByEmailAsync(userCommand.Username);

            if (user == null)
                return Unauthorized(new
                {
                    errorCode = -1,

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
                    return Unauthorized(new
                    {
                        errorCode = -2,
                    });
                if (device.UserId != user.Id)
                    return Unauthorized(new
                    {
                        errorCode = -3,
                    });
                if (user.TwoFactorEnabled)
                {
                    //var twoFactorAuthToken = await userManager.GenerateTwoFactorTokenAsync(user,"Email");
                    var twoFactorAuthToken = GenerateRandomNum();
                    if (twoFactorAuthToken != null)
                    {
                        MailData mailMessage = new MailData(new string[] { user.Email }, "OTP Confirmation", twoFactorAuthToken.ToString());
                        try
                        {
                            await _mailService.SendEmail(mailMessage);
                            Otptoken otptoken = new() { Token = twoFactorAuthToken, Userid = user.Id, Verifiedat = DateTime.Now }; 
     
                            tcuContext.Otptokens.Add(otptoken);
                            tcuContext.SaveChanges();
                            return Ok("otp code sent");
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine(ex.ToString());       
                        }
                        
                    
                    }
                }
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
            return Unauthorized(new
            {
                errorCode = -2
            });
            /*return Unauthorized(new JObject
                    {
                        new JProperty("error", -5)
                    });*/
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


        private int GenerateRandomNum()
        {
            int min = 1000;
            int max = 9999;
            Random random = new Random();
            return random.Next(min, max);
        }

        [HttpPost("verifymail")]
        public async Task<IActionResult> VerifyMail([FromBody] VerifyUserCommand verifyUserCommand)
        {
            
            var user = await userManager.FindByEmailAsync(verifyUserCommand.UserEmail);
            var device = (from _device in tcuContext.Devices where _device.DeviceId == verifyUserCommand.DeviceId select _device).FirstOrDefault();

            if (user == null)
            {
                return BadRequest("user not found");
            }
            
            if (device == null)
            {
                return BadRequest("device not found");
            }

            var OTP = (from _OTP in tcuContext.Otptokens where _OTP.Token == int.Parse(verifyUserCommand.Token) && _OTP.Userid == verifyUserCommand.Token select _OTP).FirstOrDefault();
            if(OTP != null) {
                DateTime currentTime = DateTime.Now;
                TimeSpan difference = currentTime.Subtract((DateTime)OTP.Verifiedat);
                if (difference.TotalSeconds <= 45 && difference.Days == 0 && difference.Hours ==0 && difference.Minutes ==0)
                {
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
                   

                    var _token = GenerateJwtToken(authClaims);
                    user.TwoFactorEnabled = false;
                    user.EmailConfirmed = true;
                    return Ok(new
                    {
                        _token = new JwtSecurityTokenHandler().WriteToken(_token),
                        expiration = _token.ValidTo,
                        username = user.UserName,
                        email = user.Email,
                    });
                }
               
            }
            return BadRequest("Invalid Token");
  

        }

    }
    



}

