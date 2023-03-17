using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;
using Microsoft.AspNetCore.Identity;
using Newtonsoft.Json;
using System.Security.Claims;

namespace BlazorServerAuthDemo.Shared
{
    public class AppAuthenticationStateProvider : AuthenticationStateProvider, IDisposable
    {
        public IdentityUser CurrentUser { get; private set; } = new();
        private readonly ProtectedLocalStorage _protectedLocalStorage;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;

        public AppAuthenticationStateProvider(ProtectedLocalStorage protectedLocalStorage,
            UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager)
        {
            _protectedLocalStorage = protectedLocalStorage;
            _userManager = userManager;
            _signInManager = signInManager;
            AuthenticationStateChanged += OnAuthenticationStateChangedAsync;
        }

        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            var principal = new ClaimsPrincipal();

            try
            {
                var storedPrincipal = await _protectedLocalStorage.GetAsync<string>("identity");

                if (storedPrincipal.Success)
                {
                    var storedUser = JsonConvert.DeserializeObject<StoredUserInfo>(storedPrincipal.Value);
                    var user = await _userManager.FindByIdAsync(storedUser.Id);
                    if (user != null && user.SecurityStamp == storedUser.SecurityStamp)
                    {
                        var identity = CreateIdentityFromUser(user);
                        principal = new(identity);
                        CurrentUser = user;
                    }
                }
            }
            catch
            {
                //todo
            }

            return new AuthenticationState(principal);
        }

        public async Task<bool> LoginAsync(LoginFormModel loginFormModel)
        {
            var user = await _userManager.FindByEmailAsync(loginFormModel.Email);
            if (user == null)
            {
                return false;
            }
            var singInResult = await _signInManager.CheckPasswordSignInAsync(user, loginFormModel.Password, false);

            if (!singInResult.Succeeded)
            {
                return false;
            }
            await SetAuthenticationState(user);
            return true;
        }

        public async Task LogoutAsync()
        {
            await _protectedLocalStorage.DeleteAsync("identity");
            var principal = new ClaimsPrincipal();
            NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(principal)));
        }

        public async Task SetAuthenticationState(IdentityUser user)
        {
            var identity = CreateIdentityFromUser(user);
            var principal = new ClaimsPrincipal(identity);
            var storedUser = new StoredUserInfo
            {
                Id = user.Id,
                Email = user.Email,
                SecurityStamp = user.SecurityStamp
            };
            await _protectedLocalStorage.SetAsync("identity", JsonConvert.SerializeObject(storedUser));
            NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(principal)));
        }

        public void Dispose() => AuthenticationStateChanged -= OnAuthenticationStateChangedAsync;

        private static ClaimsIdentity CreateIdentityFromUser(IdentityUser user)
        {
            var claims = new Claim[]
            {
                new (ClaimTypes.NameIdentifier, user.Id),
                new (ClaimTypes.Email, user.Email),
                new ("SecurityStamp", user.SecurityStamp)
            };
            return new ClaimsIdentity(claims, "auth");
        }

        private async void OnAuthenticationStateChangedAsync(Task<AuthenticationState> task)
        {
            var authenticationState = await task;

            if (authenticationState != null)
            {
                var userId = (await task).User.FindFirstValue(ClaimTypes.NameIdentifier);
                if (userId != null)
                {
                    CurrentUser = await _userManager.FindByIdAsync(userId);
                }
            }
        }


        private class StoredUserInfo
        {
            public string Id { get; set; }
            public string Email { get; set; }
            public string SecurityStamp { get; set; }
        }
    }

    
}


