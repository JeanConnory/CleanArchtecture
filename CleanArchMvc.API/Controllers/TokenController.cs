using CleanArchMvc.API.Models;
using CleanArchMvc.Domain.Account;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace CleanArchMvc.API.Controllers
{
	[Route("api/[controller]")]
	[ApiController]
	public class TokenController : ControllerBase
	{
		private readonly IAuthenticate _authenticate;
		private readonly IConfiguration _configuration;

		public TokenController(IAuthenticate authenticate, IConfiguration configuration)
		{
			_authenticate = authenticate;
			_configuration = configuration;
		}

		[HttpPost("CreateUser")]
		[ApiExplorerSettings(IgnoreApi = true)]
		[Authorize]
		public async Task<ActionResult<UserToken>> CreateUser([FromBody] LoginModel userInfo)
		{
			var result = await _authenticate.RegisterUser(userInfo.Email, userInfo.Password);

			if (result)
			{
				//return GenerateToken(userInfo);
				return Ok($"User {userInfo.Email} was created successfully");
			}
			else
			{
				ModelState.AddModelError(string.Empty, "Invalid login attempt");
				return BadRequest();
			}
		}

		[AllowAnonymous]
		[HttpPost("LoginUser")]
		public async Task<ActionResult<UserToken>> Login([FromBody] LoginModel userInfo)
		{
			var result = await _authenticate.Authenticate(userInfo.Email, userInfo.Password);

			if(result)
			{
				return GenerateToken(userInfo);
				//return Ok($"User {userInfo.Email} login successfully");
			}
			else
			{
				ModelState.AddModelError(string.Empty, "Invalid login attempt");
				return BadRequest();
			}
		}

		private UserToken GenerateToken(LoginModel userInfo)
		{
			//Declarações do usuário
			var claims = new[]
			{
				new Claim("email", userInfo.Email),
				new Claim("meu valor", "Qualquer valor"),
				new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
			};

			//Gerar chave privada para assinar o token
			var privateKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:SecretKey"]));

			//Gerar assinatura digital
			var credentials = new SigningCredentials(privateKey, SecurityAlgorithms.HmacSha256);

			//Definir o tempo de expiração
			var expiration = DateTime.UtcNow.AddMinutes(10);

			//Gerar Token
			JwtSecurityToken token = new JwtSecurityToken
				(
					issuer: _configuration["Jwt:Issuer"],
					audience: _configuration["Jwt:Audience"],
					claims: claims,
					expires: expiration,
					signingCredentials: credentials
				);

			return new UserToken()
			{
				Token = new JwtSecurityTokenHandler().WriteToken(token),
				Expiration = expiration
			};
		}
	}
}
