using AuthenticationServer.Data;
using AuthenticationServer.Data.Commands;
using AuthenticationServer.Models;
using AuthenticationServer.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Org.BouncyCastle.Security;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace AuthenticationServer.Controllers
{
    [Route("authentication/mobile")]
    [ApiController]
    public class MobileDeviceAuthenticationController : BaseController
    {

        private const int MIN_OTP_LENGTH = 1000;
        private const int MAX_OTP_LENGTH = 10000;
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
            var device = (from _device in tcuContext.Devices
                          where _device.DeviceId == userCommand.DeviceId
                          select _device).FirstOrDefault();
            if (device == null)
                return Unauthorized();
            if (device.UserId != user.Id)
                return Unauthorized();
            var verifyMail = user.TwoFactorEnabled || user.EmailConfirmed == false;
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
                return Ok("OTP code sent");
            }
            device.LastLoginTime = DateTime.UtcNow;
            var ipAddress = Request.HttpContext.Connection.RemoteIpAddress;
            if (ipAddress != null)
                device.IpAddress = ipAddress.ToString();
            await tcuContext.SaveChangesAsync();
            var authClaims = await GetUserClaims(user);
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
                       && _OTP.Userid == verifyUserCommand.Token 
                       select _OTP).FirstOrDefault();
            if (OTP == null)
                return Forbid();
            if (OTP.Verifiedat == null)
                return Forbid();
            var expiryDate = (DateTime)OTP.Verifiedat;
            if (currentTime <= expiryDate.AddSeconds(45))
                return StatusCode(StatusCodes.Status419AuthenticationTimeout, "OTP expired");
            var authClaims = await GetUserClaims(user);
            authClaims.Add(new Claim("deviceId", device.DeviceId.ToString()));
            var _token = GenerateJwtToken(authClaims);
            user.EmailConfirmed = true;
            return Ok(new
            {
                _token = new JwtSecurityTokenHandler().WriteToken(_token),
                expiration = _token.ValidTo,
                username = user.UserName,
                email = user.Email
            });
        }
    }
}

