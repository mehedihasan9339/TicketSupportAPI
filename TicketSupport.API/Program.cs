using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;
using TicketSupport.DAL.Context;
using TicketSupport.DAL.Data.Entity.Auth;


var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddDbContext<databaseContext>(option => option.UseSqlServer(builder.Configuration.GetConnectionString("MyConnection")));

builder.Services.AddIdentity<ApplicationUser, IdentityRole>(option =>
{
	option.SignIn.RequireConfirmedEmail = false;
	option.SignIn.RequireConfirmedPhoneNumber = false;
	option.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789";
	option.Password.RequireDigit = true;
	option.Password.RequiredLength = 6;
	option.Password.RequireLowercase = false;
	option.Password.RequireNonAlphanumeric = false;
	option.Password.RequireUppercase = false;
})
.AddEntityFrameworkStores<databaseContext>()
.AddDefaultTokenProviders();

builder.Services.AddAuthentication(option =>
{
	option.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
	option.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
	option.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
})
	.AddJwtBearer(option =>
	{
		option.SaveToken = true;
		option.RequireHttpsMetadata = false;
		option.TokenValidationParameters = new TokenValidationParameters()
		{
			ValidateIssuer = true,
			ValidateAudience = true,
			ValidIssuer = builder.Configuration["JWT:ValidIssuer"],
			ValidAudience = builder.Configuration["JWT:ValidAudience"],
			IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:SecretKey"]))
		};
	});

builder.Services.Configure<DataProtectionTokenProviderOptions>(option =>
{
	option.TokenLifespan = TimeSpan.FromHours(2);
});


builder.Services.AddSwaggerGen(c =>
{
	c.SwaggerDoc("v1", new OpenApiInfo
	{
		Title = "JWTAuth2019V5",
		Version = "v1",
		Description = "Authentication and Authorization in ASP.NET Core 5.0 With JWT & Swagger"
	});
	c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme()
	{
		Name = "Authorization",
		Type = SecuritySchemeType.ApiKey,
		Scheme = "Bearer",
		BearerFormat = "JWT",
		In = ParameterLocation.Header,
		Description = "Enter `Bearer` [space] and then your valid token in the text input below, \r\n\r\nExample: \"Bearer sasasasasasasasa\""
	});
	c.AddSecurityRequirement(new OpenApiSecurityRequirement()
				{
					{
						new OpenApiSecurityScheme
						{
							Reference = new OpenApiReference
							{
								Type = ReferenceType.SecurityScheme,
								Id = "Bearer"
							}
						}, new string[]{}
					}
				});
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
	app.UseSwagger();
	app.UseSwaggerUI();
}

app.UseAuthorization();

app.MapControllers();

app.Run();
