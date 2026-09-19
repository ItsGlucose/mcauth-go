# mcauth-go

Go port of [azalea-rs/azalea](https://github.com/azalea-rs/azalea)'s Minecraft Java Microsoft authentication (`azalea-auth`).

In-memory only: device-code login (Microsoft) → Xbox Live → XSTS → `login_with_xbox` → profile. No printing, no file I/O; the caller renders the `DeviceCode` and persists the result.

## Install

```sh
go get github.com/ItsGlucose/mcauth-go
```

## Usage

```go
c := mcauth.Default()
ctx := context.Background()

code, _ := c.GetLinkCode(ctx)
// show code.VerificationURI + code.UserCode to the user
msa, _ := c.PollToken(ctx, code)

mc, _ := c.MinecraftToken(ctx, msa.Data.AccessToken)
profile, _ := c.GetProfile(ctx, mc.MinecraftAccessToken)
ownsGame, _ := c.CheckOwnership(ctx, mc.MinecraftAccessToken)

account := mcauth.CachedAccount{
    CacheKey: profile.Name, // or email; "email" also accepted on read
    MSA:      msa,
    XBL:      mc.XBL,
    MCA:      mc.MCA,
    Profile:  profile,
}
// persist: json.Marshal([]mcauth.CachedAccount{account})
```

Refresh with `c.RefreshToken(ctx, msa.Data.RefreshToken)`. Default client ID is the Nintendo Switch one (`00000000441cc96b`), which also works for under-18 accounts.

`Skins`/`Capes` in `ProfileResponse` are `json.RawMessage` so new Mojang fields pass through untouched.
