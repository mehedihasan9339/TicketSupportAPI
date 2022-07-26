using System.ComponentModel.DataAnnotations;

namespace TicketSupport.API.Models
{
	public class ChangePasswordViewModel
	{
		[Required(ErrorMessage = "Username is required")]
		public string username { get; set; }
		[Required(ErrorMessage = "Current Password is required")]
		public string currentPassword { get; set; }
		[Required(ErrorMessage = "New Password is required")]
		public string newPassword { get; set; }
		[Required(ErrorMessage = "Confirm Password is required")]
		public string confirmPassword { get; set; }
	}
}
