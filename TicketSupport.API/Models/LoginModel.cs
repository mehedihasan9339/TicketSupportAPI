using System.ComponentModel.DataAnnotations;

namespace TicketSupport.API.Models
{
	public class LoginModel
	{
		[Required(ErrorMessage = "Username is required")]
		public string userName { get; set; }
		[Required(ErrorMessage = "Password is required")]
		public string password { get; set; }
	}
}
