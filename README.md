# JWT-Token-Base-Authntication in asp.net core Using Entity FrameWorkCore

1. Install the following packages
 
   a.   Microsoft.EntityFrameworkCore.SqlServer
   b.   Microsoft.EntityFrameworkCore.Tools
   c.   Microsoft.AspNetCore.Authentication
   d.   Microsoft.AspNetCore.Authentication.JwtBearer
2. Configuration in startup.cs file
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {

            services.AddControllers();
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "Libra_Cabel_Billing_API", Version = "v1" });
            });

            // **************** JWT ***********************
            services
               .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
               .AddJwtBearer(options =>
               {
                   
                   var serverSecret = new SymmetricSecurityKey(Encoding.UTF8. GetBytes(Configuration["JWT:key"]));
                   options.SaveToken = true;
                   options.TokenValidationParameters = new TokenValidationParameters
                   {
                       ValidateIssuer = false,
                       ValidateAudience = false,
                       ValidateLifetime = true,
                       IssuerSigningKey = serverSecret,
                       ValidIssuer = Configuration["JWT:Issuer"],
                       ValidAudience = Configuration["JWT:Audience"]
                   };
               });

            services.AddSingleton<IJWTManagerRepo, JWTManagerRepo>();


        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseSwagger();
                app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "Libra_Cabel_Billing_API v1"));
            }

            app.UseHttpsRedirection();

            app.UseRouting();
            app.UseAuthentication(); // This need to be added	
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }

3. Create the controller for authtication
 
 public class JWTController : ControllerBase
    {
        private IConfiguration _config;
        private IJWTManagerRepo _iJWTManagerRepo;

        public JWTController(IConfiguration config, IJWTManagerRepo iJWTManagerRepo)
        {
            _config = config;
            _iJWTManagerRepo = iJWTManagerRepo;
        }
        [AllowAnonymous]
        [HttpPost("AuthenticateUser")]
        public  IActionResult CreateToken([FromBody] LoginModel login)
        {
            IActionResult response = Unauthorized();
            var Token =  _iJWTManagerRepo.AuthenticateUser(login);
            if (!string.IsNullOrEmpty(Token.Result))
            {    
                response = Ok(new { token = Token });
            }

           } 
     }
     
  4. Create Services
   public interface IJWTManagerRepo
    {
        Task<string> AuthenticateUser(LoginModel user);
        
    }
  
      public class JWTManagerRepo : IJWTManagerRepo
    {
        private Billing_DB_Backup_May_2022Context _context;
        private IConfiguration _config;
        public JWTManagerRepo(IConfiguration config)
        {
            _context = new Billing_DB_Backup_May_2022Context();
            _config = config;
        }

        public async Task<string> AuthenticateUser(LoginModel user)
        {
            
            string token = "";
            var res = await _context.AdminTbls.Where(x=>x.UserName==user.Username && x.Passwrd==user.Password).FirstOrDefaultAsync();
            if(res!=null)
            {
                token = BuildToken(res);
            }              
            return token;
        }
        #region BuildToken
        private string BuildToken(AdminTbl user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            // tokenDescriptor
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                  {
                     new Claim(ClaimTypes.Name, user.UserName)
                  }),
                Expires = DateTime.UtcNow.AddMinutes(10),
                SigningCredentials = creds,
                Issuer = _config["Jwt:Issuer"]
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var BearerToken = tokenHandler.WriteToken(token);
            return BearerToken;
        }
        #endregion


    }




 
