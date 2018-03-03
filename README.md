# Rubyhome-SRP

Secure Remote Password protocol (SRP-6a) with HomeKit Accessory Protocol Specification (HAP) modifications.

- SHA-512 is used as the hash function, replacing SHA-1
- The Modulus, N, and Generator, g, are specified by the 3072-bit group of [RFC 5054](https://tools.ietf.org/html/rfc5054)

## References

- [RFC 2945](https://tools.ietf.org/html/rfc2945)
- [RFC 5054](https://tools.ietf.org/html/rfc5054)
- [Homekit accessory protocol specification (non-commercial version)](https://developer.apple.com/documentation/homekit)

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'rubyhome-srp'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install rubyhome-srp

## Contributing

Contributions are welcome, please follow [GitHub Flow](https://guides.github.com/introduction/flow/index.html)

## Credit

The original SRP-6a work was done by [lamikae](https://github.com/lamikae/) in the [srp-rb](https://github.com/lamikae/srp-rb) project.
