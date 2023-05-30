using AuthenticationServer.Data;
using AuthenticationServer.Data.Commands;
using AuthenticationServer.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Org.BouncyCastle.Security;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;


namespace AuthenticationServer.Controllers
{
    [Route("authentication/mobile/shareAccess")]
    [ApiController]
    public class ShareVehicleAccessController : BaseController
    {
        public ShareVehicleAccessController(TcuContext tcuContext, UserManager<IdentityUser> userManager, IConfiguration config) : base(tcuContext, userManager, config)
        {
        }


        [HttpPost]
        [Route("request")]
        [Authorize(Policy = "ShareAccess")]
        public async Task<IActionResult> RequestAccess()
        {
            if (User.Identity == null)
                return Unauthorized();

            string? deviceId = (from _claim in User.Claims
                              where _claim.Type == "deviceId"
                              select _claim.Value).FirstOrDefault();
            
            if (deviceId == null)
                return Unauthorized();

            var device = (from _device in tcuContext.Devices
                          where _device.DeviceId == deviceId
                          select _device).FirstOrDefault();
            
            if (device == null)
                return Unauthorized();

            string? userId = (from _claim in User.Claims
                                where _claim.Type == ClaimTypes.NameIdentifier
                                select _claim.Value).FirstOrDefault();
            
            if (userId == null)
                return Unauthorized();

            IdentityUser user = await userManager.FindByIdAsync(userId);

            var tcu = (from _tcu in tcuContext.Tcus
                       where _tcu.UserId == user.Id
                       select _tcu).FirstOrDefault();
            
            if (tcu == null)
                return Forbid();

            SecureRandom secureRandom = new();
            var token = secureRandom.Next(MIN_OTP_LENGTH, MAX_OTP_LENGTH).ToString();
            ConnectionRequest connectionRequest = new()
            {
                TcuId = tcu.TcuId,
                DeviceId = device.DeviceId,
                CreationTimeStamp = DateTime.Now,
                Token = token,
                StatusId = 0
            };

            tcuContext.ConnectionRequests.Add(connectionRequest);
            tcuContext.SaveChanges();

            return Ok(new
            {
                token,
                tcuId = tcu.TcuId
            });
        }

        [HttpPost]
        [Route("request")]
        [AllowAnonymous]
        public async Task<IActionResult> SubmitRequestAccess([FromBody] VehicleAccessRequestCommand command)
        {
            var currentTime = DateTime.Now;
            ConnectionRequest? connectionRequest = (from _request in tcuContext.ConnectionRequests
                                                   where _request.TcuId == command.TcuId
                                                   && _request.Token == command.Token
                                                   select _request).FirstOrDefault();
            if (connectionRequest == null)
                return Forbid();
            if (connectionRequest.StatusId != 0)
                return Forbid();

            var expiryDate = connectionRequest.CreationTimeStamp;
            if (currentTime >= expiryDate.AddSeconds(45))
            {
                connectionRequest.StatusId = 1;
                tcuContext.SaveChanges();
                return StatusCode(StatusCodes.Status419AuthenticationTimeout, "request expired");
            }


            var userId = (from _device in tcuContext.Devices
                          where _device.DeviceId == connectionRequest.DeviceId
                          select _device.UserId).FirstOrDefault();

            if (userId == null)
                return BadRequest();

            connectionRequest.StatusId = 2;

            string? ipAdress = ResolveIPAddress(Request.HttpContext);
            
            var newDevice = new Device
            {
                UserId = userId,
                LastLoginTime = DateTime.Now,
                IpAddress = ipAdress,
                NotificationToken = command.NotificationToken,
            };

            tcuContext.Devices.Add(newDevice);
            tcuContext.SaveChanges();
            var user = await userManager.FindByIdAsync(userId);
            var authClaims = await GetUserClaims(user);
            authClaims.Add(new Claim("deviceId", newDevice.DeviceId.ToString()));
            var token = GenerateJwtToken(authClaims);
            return Ok(new
            {
                token = new JwtSecurityTokenHandler().WriteToken(token),
                expiration = token.ValidTo,
                username = user.UserName,
                email = user.Email,
            });
        }
    }
}
