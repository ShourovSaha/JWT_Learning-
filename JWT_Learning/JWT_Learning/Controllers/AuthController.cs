using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using JWT_Learning.JWTAuthentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace JWT_Learning.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly IConfiguration configuration;

        public AuthController(UserManager<ApplicationUser> userManager,
                                SignInManager<ApplicationUser> signInManager,
                                RoleManager<IdentityRole> roleManager,
                                IConfiguration configuration)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.roleManager = roleManager;
            this.configuration = configuration;
        }


        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return StatusCode(StatusCodes.Status404NotFound, new ResponseModel
                    {
                        Status = "1001",
                        Message = "failed."
                    });
                }

                var existingbUser = await userManager.FindByNameAsync(model.Username);
                if (existingbUser != null) return StatusCode(StatusCodes.Status500InternalServerError);

                ApplicationUser user = new ApplicationUser()
                {
                    UserName = model.Username,
                    Email = model.Email,
                    SecurityStamp = Guid.NewGuid().ToString()
                };

                var result = await userManager.CreateAsync(user, model.Password);

                if (!result.Succeeded) return StatusCode(StatusCodes.Status500InternalServerError, new ResponseModel
                {
                    Status = "1001",
                    Message = "failed."
                });

                return StatusCode(StatusCodes.Status200OK, new ResponseModel
                {
                    Status = "1000",
                    Message = "Success."
                });
            }
            catch (Exception ex)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new ResponseModel
                {
                    Status = "1000",
                    Message = ex.Message
                });
            }
        }

        [HttpPost]
        [Route("Register-Admin")]
        public async Task<IActionResult> RegisterAdmin([FromBody] RegisterModel model)
        {
            if (!ModelState.IsValid)
            {
                return StatusCode(StatusCodes.Status404NotFound, new ResponseModel
                {
                    Status = "1001",
                    Message = "failed."
                });
            }

            var existingbUser = await userManager.FindByNameAsync(model.Username);
            if (existingbUser != null) return StatusCode(StatusCodes.Status500InternalServerError);

            ApplicationUser user = new ApplicationUser()
            {
                UserName = model.Username,
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString()
            };

            var result = await userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded) return StatusCode(StatusCodes.Status500InternalServerError, new ResponseModel
            {
                Status = "1001",
                Message = "failed."
            });


            if (!await roleManager.RoleExistsAsync(UserRoles.Admin))
                await roleManager.CreateAsync(new IdentityRole(UserRoles.Admin));

            if (!await roleManager.RoleExistsAsync(UserRoles.User))
                await roleManager.CreateAsync(new IdentityRole(UserRoles.User));

            if (await roleManager.RoleExistsAsync(UserRoles.Admin))
                await userManager.AddToRoleAsync(user, UserRoles.Admin);

            return StatusCode(StatusCodes.Status200OK, new ResponseModel
            {
                Status = "1000",
                Message = "Success."
            });
        }


        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            try
            {
                var existingUser = await userManager.FindByNameAsync(model.Username);
                if (existingUser != null &&
                     !await userManager.CheckPasswordAsync(existingUser, model.Password))
                {
                    return StatusCode(StatusCodes.Status404NotFound, new ResponseModel
                    {
                        Status = "1001",
                        Message = "failed."
                    });
                }

                var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, model.Username),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

                var userRoles = await userManager.GetRolesAsync(existingUser);

                foreach (var role in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, role));
                }

                var authSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:Secret"]));

                var token = new JwtSecurityToken(issuer: configuration["JWT:ValidIssuer"],
                                     audience: configuration["JWT:ValidAudience"],
                                     expires: DateTime.Now.AddHours(1),
                                     claims: authClaims,
                                     signingCredentials: new SigningCredentials(authSecurityKey, SecurityAlgorithms.HmacSha256)
                                     );

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    expirtion = token.ValidTo
                });
            }
            catch (Exception ex)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new ResponseModel
                {
                    Status = "1000",
                    Message = ex.Message
                });
            }

        }
    }
}