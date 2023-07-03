namespace JWTAPI.Models
{
    public class UserConstants
    {
        public List<User> Users = new List<User>()
        {
            new User 
            { 
                Id = 1,
                Username = "Test",
                Password = "test",
                Bio = "this is an admin user",
                IsAdmin = true,
                IsActive = true
            },
            new User
            {
                Id = 2,
                Username="Test2",
                Password="test",
                Bio = "this is not an admin user",
                IsAdmin = false,
                IsActive=true
            }
        };
    }
}
