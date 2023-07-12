using EmailAndPasswordApi.Models;
using Microsoft.EntityFrameworkCore;

namespace EmailAndPasswordApi.Data
{
    public class DataContext : DbContext
    {
        public DataContext(DbContextOptions<DataContext> options) : base(options)
        {
                
        }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            base.OnConfiguring(optionsBuilder);
            //may change connection string to live in either app settings or environment variables, but for now, it can be here
            optionsBuilder.UseSqlServer("Server=.\\SQLExpress;Database=userdb;Trusted_Connection=true");
        }

        public DbSet<User> Users { get; set; }
    }
}
