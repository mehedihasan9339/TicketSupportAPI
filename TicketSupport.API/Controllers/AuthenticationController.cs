using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;
using TicketSupport.API.Models;
using TicketSupport.DAL.Data.Entity.Auth;

namespace TicketSupport.API.Controllers
{
	[Route("api/[controller]")]
	[ApiController]
	public class AuthenticationController : ControllerBase
	{
		private readonly UserManager<ApplicationUser> _userManager;
		private readonly RoleManager<IdentityRole> _roleManager;
		private readonly IConfiguration _configuration;

		public AuthenticationController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
		{
			_userManager = userManager;
			_roleManager = roleManager;
			_configuration = configuration;
		}

		[HttpPost]
		[Route("register")]
		public async Task<IActionResult> Register([FromBody] RegisterModel model)
		{
			var userIsExist = await _userManager.FindByNameAsync(model.userName);

			if (userIsExist != null)
			{
				return StatusCode(StatusCodes.Status500InternalServerError, new Response { status = "Error", message = "User already exists" });
			}

			var user = new ApplicationUser
			{
				UserName = model.userName,
				Email = model.email,
				SecurityStamp = Guid.NewGuid().ToString()
			};

			var result = await _userManager.CreateAsync(user, model.password);

			if (!result.Succeeded)
			{
				return StatusCode(StatusCodes.Status500InternalServerError, new Response { status = "Error", message = result.ToString() });
			}
			else
			{
				return Ok(new Response { status = "Sucess", message = "User created successfully" });
			}
		}


		[HttpPost]
		[Route("register-admin")]
		public async Task<IActionResult> RegisterAdmin([FromBody] RegisterModel model)
		{
			var userIsExist = await _userManager.FindByNameAsync(model.userName);

			if (userIsExist != null)
			{
				return StatusCode(StatusCodes.Status500InternalServerError, new Response { status = "Error", message = "User already exists" });
			}

			var user = new ApplicationUser
			{
				UserName = model.userName,
				Email = model.email,
				SecurityStamp = Guid.NewGuid().ToString()
			};

			var result = await _userManager.CreateAsync(user, model.password);

			if (!result.Succeeded)
			{
				return StatusCode(StatusCodes.Status500InternalServerError, new Response { status = "Error", message = result.ToString() });
			}

			if (!await _roleManager.RoleExistsAsync(UserRoles.Admin))
			{
				await _roleManager.CreateAsync(new IdentityRole(UserRoles.Admin));
			}
			if (!await _roleManager.RoleExistsAsync(UserRoles.User))
			{
				await _roleManager.CreateAsync(new IdentityRole(UserRoles.User));
			}
			if (!await _userManager.IsInRoleAsync(user, UserRoles.Admin))
			{
				await _userManager.AddToRoleAsync(user, UserRoles.Admin);
			}

			return Ok(new Response { status = "Sucess", message = "User created successfully" });
		}


		[HttpPost]
		[Route("login")]
		public async Task<IActionResult> Login([FromBody] LoginModel model)
		{
			var user = await _userManager.FindByNameAsync(model.userName);
			if (user != null && await _userManager.CheckPasswordAsync(user, model.password))
			{
				var userRoles = await _userManager.GetRolesAsync(user);

				var authClaims = new List<Claim>
				{
					new Claim(ClaimTypes.Name, user.UserName),
					new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
				};

				foreach (var userRole in userRoles)
				{
					authClaims.Add(new Claim(ClaimTypes.Role, userRole));
				}

				var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:SecretKey"]));

				var token = new JwtSecurityToken(
						issuer: _configuration["JWT:ValidIssuer"],
						audience: _configuration["JWT:ValidAudience"],
						expires: DateTime.Now.AddHours(1),
						claims: authClaims,
						signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
					);
				return Ok(new { token = new JwtSecurityTokenHandler().WriteToken(token), expiration = token.ValidTo });
			};
			return Unauthorized();
		}

		[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
		[HttpPost]
		[Route("change-password")]
		public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordViewModel model)
		{
			var user = await _userManager.FindByNameAsync(model.username);
			if (user == null)
			{
				return StatusCode(StatusCodes.Status404NotFound, new Response { status = "Error", message = "User not found" });
			}
			if (string.Compare(model.newPassword, model.confirmPassword) != 0)
			{
				return StatusCode(StatusCodes.Status400BadRequest, new Response { status = "Error", message = "Password missmatch" });
			}

			var result = await _userManager.ChangePasswordAsync(user, model.currentPassword, model.newPassword);

			if (!result.Succeeded)
			{
				var errors = new List<string>();
				foreach (var item in result.Errors)
				{
					errors.Add(item.Description);
				}
				return StatusCode(StatusCodes.Status500InternalServerError, new Response { status = "Error", message = string.Join(',', errors) });
			}

			return Ok(new Response { status = "Success", message = "Password Changed Successfully" });
		}


		[Authorize(Roles = "Admin")]
		[HttpPost]
		[Route("reset-password-admin")]
		public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordViewModel model)
		{
			var user = await _userManager.FindByNameAsync(model.username);
			if (user == null)
			{
				return StatusCode(StatusCodes.Status404NotFound, new Response { status = "Error", message = "User not found" });
			}
			if (string.Compare(model.newPassword, model.confirmPassword) != 0)
			{
				return StatusCode(StatusCodes.Status400BadRequest, new Response { status = "Error", message = "Password missmatch" });
			}

			var token = await _userManager.GeneratePasswordResetTokenAsync(user);

			if (string.IsNullOrEmpty(token))
			{
				return StatusCode(StatusCodes.Status400BadRequest, new Response { status = "Error", message = "Invalid Token" });
			}

			var result = await _userManager.ResetPasswordAsync(user, token, model.newPassword);

			if (!result.Succeeded)
			{
				var errors = new List<string>();
				foreach (var item in result.Errors)
				{
					errors.Add(item.Description);
				}
				return StatusCode(StatusCodes.Status500InternalServerError, new Response { status = "Error", message = string.Join(',', errors) });
			}

			return Ok(new Response { status = "Success", message = "Password Changed Successfully" });
		}

		[HttpPost]
		[Route("reset-password-token")]
		public async Task<IActionResult> ResetPasswordToken([FromBody] ResetPasswordTokenViewModel model)
		{
			var user = await _userManager.FindByNameAsync(model.username);
			if (user == null)
			{
				return StatusCode(StatusCodes.Status404NotFound, new Response { status = "Error", message = "User not found" });
			}

			var token = await _userManager.GeneratePasswordResetTokenAsync(user);

			return Ok(new { token = token });
		}



		[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
		[HttpGet]
		[Route("testAction")]
		public IActionResult TestAction()
		{
			return Ok(new { message = "Hello World!" });
		}

		[HttpGet]
		[Route("testAction2")]
		public IActionResult TestAction2()
		{
			return Ok(new { message = "Hello World!" });
		}

	}
}
