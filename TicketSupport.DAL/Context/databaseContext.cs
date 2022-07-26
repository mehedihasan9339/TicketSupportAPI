using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using TicketSupport.DAL.Data.Entity.Auth;

namespace TicketSupport.DAL.Context
{
	public class databaseContext : IdentityDbContext<ApplicationUser>
	{
		public databaseContext(DbContextOptions<databaseContext> options) : base(options)
		{

		}
	}
}
