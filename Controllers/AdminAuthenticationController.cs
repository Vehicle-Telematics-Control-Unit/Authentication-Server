using AuthenticationServer.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationServer.Controllers
{
    [Route("api/Admin")]
    [ApiController]
    public class AdminAuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> userManager;
        private readonly TcuContext tcuContext;
        private readonly IConfiguration _config;

        public AdminAuthenticationController(UserManager<IdentityUser> userManager, TcuContext tcuContext, IConfiguration config)
        {
            this.userManager = userManager;
            this.tcuContext = tcuContext;
            _config = config;
        } 

        [HttpPost]
        [Route("register")]
      
        public async Task<IActionResult> Register(string username, string email, string password)
        {
            var userByEmail = await userManager.FindByEmailAsync(email);
            var userByUsername = await userManager.FindByNameAsync(username);
            if (userByEmail is not null || userByUsername is not null)
            {
                return Conflict($"User with email {email} or username {username} already exists.");
                
            }

            IdentityUser user = new()
            {
                Email = email,
                UserName = username,
                SecurityStamp = Guid.NewGuid().ToString(),
                TwoFactorEnabled=true
            };

            var result = await userManager.CreateAsync(user, password);
            await tcuContext.SaveChangesAsync();

            if (!result.Succeeded)
            {
                throw new ArgumentException($"Unable to register user {username} errors: {(result.Errors.ToString)}");
            }

            return Ok("user is registered");

        }

    }
}
