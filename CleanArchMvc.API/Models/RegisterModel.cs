using System.ComponentModel.DataAnnotations;
using System.Xml.Linq;

namespace CleanArchMvc.API.Models
{
	public class RegisterModel
	{
		[Required]
		[EmailAddress]
		public string Email { get; set; }

		[Required]
		[DataType(DataType.Password)]
		public string Password { get; set; }


		[Display(Name = "Confirm Password")]
		[DataType(DataType.Password)]
		[Compare("Password", ErrorMessage = "Password don't match")]
		public string ConfirmPassword { get; set; }
	}
}
