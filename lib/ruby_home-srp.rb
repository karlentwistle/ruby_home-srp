require 'securerandom'
require 'srp'
require_relative 'ruby_home-srp/core_ext/integer'

module RubyHome
  module SRP
    class << self
      ::SRP.singleton_methods.each do |m|
        define_method m, ::SRP.method(m).to_proc
      end
    end

    class << self
      def sha512_hex(h)
        OpenSSL::Digest::SHA512.hexdigest([h].pack('H*'))
      end

      def sha512_str(s)
        OpenSSL::Digest::SHA512.hexdigest(s)
      end

      # hashing function with padding.
      # Input is prefixed with 0 to meet N hex width.
      def H(n, *a)
        nlen = 2 * (((n.to_hex_string).length * 4 + 7) >> 3)
        hashin = a.map {|s|
          next unless s
          shex = s.class == String ? s : s.to_hex_string
          if shex.length > nlen
            raise 'Bit width does not match - client uses different prime'
          end
          '0' * (nlen - shex.length) + shex
        }.join('')
        sha512_hex(hashin).hex % n
      end

      # Multiplier parameter
      # k = H(N, g)   (in SRP-6a)
      def calc_k(n, g)
        H(n, n, g)
      end

      # Private key (derived from username, raw password and salt)
      # x = H(salt || H(username || ':' || password))
      def calc_x(username, password, salt)
        sha512_hex(salt + sha512_str([username, password].join(':'))).hex
      end

      # Random scrambling parameter
      # u = H(A, B)
      def calc_u(xaa, xbb, n)
        H(n, xaa, xbb)
      end

      # M = H(H(N) xor H(g), H(I), s, A, B, K)
      def calc_M(username, xsalt, xaa, xbb, xkk, n, g)
        hn = sha512_hex(n.to_hex_string).hex
        hg = sha512_hex(g).hex
        hxor = (hn ^ hg).to_hex_string
        hi = sha512_str(username)

        hashin = [hxor, hi, xsalt, xaa, xbb, xkk].join
        sha512_hex(hashin).hex % n
      end

      # H(A, M, K)
      def calc_H_AMK(xaa, xmm, xkk, n, g)
        hashin = [xaa, xmm, xkk].join()
        sha512_hex(hashin).hex % n
      end

      def Ng(group)
        case group
        when 3072
          @N = %w{
            FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08
            8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B
            302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9
            A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6
            49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8
            FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
            670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C
            180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718
            3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D
            04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D
            B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226
            1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
            BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC
            E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF
          }.join.hex
          @g = '05'
        else
          raise NotImplementedError
        end
        return [@N, @g]
      end
    end

    class Verifier < ::SRP::Verifier
      attr_reader :u
      attr_writer :salt, :b

      def initialize group=3072
        # select modulus (N) and generator (g)
        @N, @g = SRP.Ng group
        @k = SRP.calc_k(@N, @g)
      end

      # Initial user creation for the persistance layer.
      # Not part of the authentication process.
      # Returns { <username>, <password verifier>, <salt> }
      def generate_userauth username, password
        @salt ||= random_salt
        x = SRP.calc_x(username, password, @salt)
        v = SRP.calc_v(x, @N, @g.hex)
        return {:username => username, :verifier => v.to_hex_string, :salt => @salt}
      end

      # Authentication phase 1 - create challenge.
      # Returns Hash with challenge for client and proof to be stored on server.
      # Parameters should be given in hex.
      def get_challenge_and_proof username, xverifier, xsalt
        generate_B(xverifier)
        return {
          :challenge => {:B => @B, :salt => xsalt},
          :proof     => {:B => @B, :b => @b.to_hex_string, :I => username, :s => xsalt, :v => xverifier}
        }
      end

      # returns H_AMK on success, None on failure
      # User -> Host:  M = H(H(N) xor H(g), H(I), s, A, B, K)
      # Host -> User:  H(A, M, K)
      def verify_session proof, client_M
        @A = proof[:A]
        @B = proof[:B]
        @b = proof[:b].to_i(16)
        username = proof[:I]
        xsalt = proof[:s]
        v = proof[:v].to_i(16)

        @u = SRP.calc_u(@A, @B, @N)
        # SRP-6a safety check
        return false if @u == 0

        # calculate session key
        @S = SRP.calc_server_S(@A.to_i(16), @b, v, @u, @N).to_hex_string
        @K = SRP.sha512_hex(@S)

        # calculate match
        @M = SRP.calc_M(username, xsalt, @A, @B, @K, @N, @g).to_hex_string

        if @M == client_M
          # authentication succeeded
          @H_AMK = SRP.calc_H_AMK(@A, @M, @K, @N, @g).to_hex_string
          return @H_AMK
        end
        return false
      end

      def random_salt
        SecureRandom.hex(16)
      end

      def random_bignum
        SecureRandom.hex(32).hex
      end

      def u
        @u.to_hex_string
      end

      # generates challenge
      # input verifier in hex
      def generate_B xverifier
        v = xverifier.to_i(16)
        @b ||= random_bignum
        @B = SRP.calc_B(@b, @k, v, @N, @g.hex).to_hex_string
      end
    end

    class Client < ::SRP::Client
      attr_writer :a

      def initialize group=3072
        # select modulus (N) and generator (g)
        @N, @g = SRP.Ng group
        @k = SRP.calc_k(@N, @g)
      end

      # Phase 1 : Step 1 : Start the authentication process by generating the
      # client 'a' and 'A' values. Public 'A' should later be sent along with
      # the username, to the server verifier to continue the auth process. The
      # internal secret 'a' value should remain private.
      #
      # @return [String] the value of 'A' in hex
      def start_authentication
        @a ||= SecureRandom.hex(32).hex
        @A = SRP.calc_A(@a, @N, @g.hex).to_hex_string
      end

      # Phase 2 : Step 1 : Process the salt and B values provided by the server.
      #
      # @param username [String] the client provided authentication username
      # @param password [String] the client provided authentication password
      # @param xsalt [String] the server provided salt for the username in hex
      # @param xbb [String] the server verifier 'B' value in hex
      # @return [String] the client 'M' value in hex
      def process_challenge(username, password, xsalt, xbb)
        raise ArgumentError, 'username must be a string' unless username.is_a?(String) && !username.empty?
        raise ArgumentError, 'password must be a string' unless password.is_a?(String) && !password.empty?
        raise ArgumentError, 'xsalt must be a string' unless xsalt.is_a?(String)
        raise ArgumentError, 'xsalt must be a hex string' unless xsalt =~ /^[a-fA-F0-9]+$/
        raise ArgumentError, 'xbb must be a string' unless xbb.is_a?(String)
        raise ArgumentError, 'xbb must be a hex string' unless xbb =~ /^[a-fA-F0-9]+$/

        # Convert the 'B' hex value to an Integer
        bb = xbb.to_i(16)

        # SRP-6a safety check
        return false if (bb % @N).zero?

        x = SRP.calc_x(username, password, xsalt)
        u = SRP.calc_u(@A, xbb, @N)

        # SRP-6a safety check
        return false if u.zero?

        # Calculate session key 'S' and secret key 'K'
        @S = SRP.calc_client_S(bb, @a, @k, x, u, @N, @g.hex).to_hex_string
        @K = SRP.sha512_hex(@S)

        # Calculate the 'M' matcher
        @M = SRP.calc_M(username, xsalt, @A, xbb, @K, @N, @g)

        # Calculate the H(A,M,K) verifier
        @H_AMK = SRP.calc_H_AMK(@A, @M.to_hex_string, @K, @N, @g).to_hex_string

        # Return the 'M' matcher to be sent to the server
        @M.to_hex_string
      end
    end
  end
end
