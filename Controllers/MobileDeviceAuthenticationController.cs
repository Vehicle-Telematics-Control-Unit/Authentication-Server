using AuthenticationServer.Data;
using AuthenticationServer.Data.Commands;
using AuthenticationServer.Models;
using AuthenticationServer.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Org.BouncyCastle.Security;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using static Microsoft.EntityFrameworkCore.DbLoggerCategory.Database;

namespace AuthenticationServer.Controllers
{
    [Route("authentication/mobile")]
    [ApiController]
    public class MobileDeviceAuthenticationController : BaseController
    {
        protected readonly IMailService _mailService;
        public MobileDeviceAuthenticationController(TcuContext tcuContext, UserManager<IdentityUser> userManager, IConfiguration config, IMailService mailService): base(tcuContext, userManager, config)
        {
            _mailService = mailService;
        }

    

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] UserCommand userCommand)
        {
            var user = await FindUser(userCommand.Username);
            if (user == null)
                return Unauthorized();
            var isCrdentialsCorrect = await userManager.CheckPasswordAsync(user, userCommand.Password);
            if (isCrdentialsCorrect == false)
                return Unauthorized();
            string? ipAdress = ResolveIPAddress(Request.HttpContext);

            if (userCommand.deviceId == null)
                return BadRequest();

            Device? device;
            device = (from _device in tcuContext.Devices
                      where _device.DeviceId == userCommand.deviceId
                      select _device).FirstOrDefault();
            if (device == null)
            {
                device = new Device
                {
                    DeviceId = userCommand.deviceId,
                    UserId = user.Id,
                    IpAddress = ipAdress
                };
                IdentityUser _user = await userManager.FindByIdAsync(user.Id);
                var tcu = (from _tcu in tcuContext.Tcus
                           where _tcu.UserId == _user.Id
                           select _tcu).FirstOrDefault();

                if (tcu == null)
                    Forbid();

                var deviceTCU = new DevicesTcu
                {
                    TcuId = tcu.TcuId,
                    DeviceId = device.DeviceId,
                    IsActive = true,
                    IsPrimary = false
                };

                tcuContext.DevicesTcus.Add(deviceTCU);
                tcuContext.Devices.Add(device);
                tcuContext.SaveChanges();
            }


            var verifyMail = user.TwoFactorEnabled || (user.EmailConfirmed == false);
            if (verifyMail)
            {

                SecureRandom secureRandom = new();
                var twoFactorAuthToken = secureRandom.Next(MIN_OTP_LENGTH, MAX_OTP_LENGTH);
                MailData mailMessage = new(new string[] { user.Email }, "OTP Confirmation", twoFactorAuthToken.ToString());
                await _mailService.SendEmail(mailMessage);
                tcuContext.Otptokens.Add(new()
                {
                    Token = twoFactorAuthToken,
                    Userid = user.Id,
                    Verifiedat = DateTime.Now
                });
                tcuContext.SaveChanges();
                return Ok(new
                {
                    message = "otp code sent",
                    email = user.Email
                });
            }

            device.NotificationToken = userCommand.NotificationToken;
            device.LastLoginTime = DateTime.UtcNow;
            
            var ipAddress = ResolveIPAddress(Request.HttpContext);
            if (ipAddress != null)
                device.IpAddress = ipAddress;
            
            await tcuContext.SaveChangesAsync();
            var authClaims = await GetUserClaims(user);
            authClaims.Add(new Claim("deviceId", device.DeviceId.ToString()));
            var token = GenerateJwtToken(authClaims);
            return Ok(new
            {
                token = new JwtSecurityTokenHandler().WriteToken(token),
                expiration = token.ValidTo,
                username = user.UserName,
                email = user.Email
            });
        }

        [HttpPost("verifymail")]
        public async Task<IActionResult> VerifyMail([FromBody] VerifyUserCommand verifyUserCommand)
        {
            DateTime currentTime = DateTime.Now;
            var user = await userManager.FindByEmailAsync(verifyUserCommand.UserEmail);
            var device = (from _device in tcuContext.Devices 
                          where _device.DeviceId == verifyUserCommand.DeviceId 
                          select _device).FirstOrDefault();
            if (user == null || device == null || verifyUserCommand.Token == null)
                return Forbid();
            var OTP = (from _OTP in tcuContext.Otptokens 
                       where _OTP.Token == int.Parse(verifyUserCommand.Token) 
                       && _OTP.Userid == user.Id
                       select _OTP).FirstOrDefault();
            if (OTP == null)
                return Forbid();
            if (OTP.Verifiedat == null)
                return Forbid();
            var expiryDate = (DateTime)OTP.Verifiedat;
            if (currentTime >= expiryDate.AddSeconds(45))
                return StatusCode(StatusCodes.Status419AuthenticationTimeout, "OTP expired");
            device.NotificationToken = verifyUserCommand.NotificationToken;
            tcuContext.SaveChanges();
            var authClaims = await GetUserClaims(user);
            authClaims.Add(new Claim("deviceId", device.DeviceId.ToString()));
            authClaims.Add(new Claim("HasPrimaryDevice", "yes"));
            var _token = GenerateJwtToken(authClaims);
            user.EmailConfirmed = true;
            return Ok(new
            {
                token = new JwtSecurityTokenHandler().WriteToken(_token),
                expiration = _token.ValidTo,
                username = user.UserName,
                email = user.Email
            });
        }
        [HttpPost("editUsername")]
        [Authorize]
        public async Task<IActionResult> EditUsername([FromBody]string newUserName)
        {
            Console.WriteLine("username is"+newUserName);
            string? deviceId = (from _claim in User.Claims
                                where _claim.Type == "deviceId"
                                select _claim.Value).FirstOrDefault();

            if (deviceId == null)
                return Unauthorized();

            string? userId = (from _claim in User.Claims
                              where _claim.Type == ClaimTypes.NameIdentifier
                              select _claim.Value).FirstOrDefault();

            if (userId == null)
                return Unauthorized();

            string? hasPrimaryDeviceClaim = (from _claim in User.Claims
                                where _claim.Type == "HasPrimaryDevice"
                                select _claim.Value).FirstOrDefault();
            if (hasPrimaryDeviceClaim == null)
                return Unauthorized();

            IdentityUser user = await userManager.FindByIdAsync(userId);

            if(user == null) 
                return Unauthorized();
            // Check if the new username already exists
            var isNewUsernameTaken = await IsUsernameTaken(newUserName);
            if (isNewUsernameTaken)
            {
                // New username is already taken, return an error response
                return BadRequest("Username is already taken.");
            }
            // Update the username
            user.UserName = newUserName;
            // Save the changes to the database
             var isUpdated=await userManager.UpdateAsync(user);
            if (isUpdated.Succeeded == false)
                return BadRequest();
            return Ok();
        }

        private async Task<bool> IsUsernameTaken(string? newUserName)
        {
            var existingUser =  await userManager.FindByNameAsync(newUserName);
            return existingUser != null;
        }

        [HttpPost("editPassword")]
        [Authorize]
        public async Task<IActionResult> EditPassword([FromBody] EditUserCommand editUserCommand)
        {
            string? deviceId = (from _claim in User.Claims
                                where _claim.Type == "deviceId"
                                select _claim.Value).FirstOrDefault();

            if (deviceId == null)
                return Unauthorized();

            string? userId = (from _claim in User.Claims
                              where _claim.Type == ClaimTypes.NameIdentifier
                              select _claim.Value).FirstOrDefault();

            if (userId == null)
                return Unauthorized();

            string? hasPrimaryDeviceClaim = (from _claim in User.Claims
                                             where _claim.Type == "HasPrimaryDevice"
                                             select _claim.Value).FirstOrDefault();
            if (hasPrimaryDeviceClaim == null)
                return Unauthorized();
            IdentityUser user = await userManager.FindByIdAsync(userId);

            var isCrdentialsCorrect = await userManager.CheckPasswordAsync(user, editUserCommand.Password);
            if (isCrdentialsCorrect == false)
                return Unauthorized();

            await userManager.ChangePasswordAsync(user, editUserCommand.Password, editUserCommand.NewPassword);

            return Ok();    

        }



    }
}

