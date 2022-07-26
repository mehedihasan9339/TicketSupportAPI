using System.ComponentModel.DataAnnotations;

namespace TicketSupport.API.Models
{
	public class RegisterModel
	{
		[Required(ErrorMessage = "Username is required")]
		public string userName { get; set; }
		[Required(ErrorMessage = "Email is required")]
		public string email { get; set; }
		[Required(ErrorMessage = "Password is required")]
		public string password { get; set; }
	}
}
