# == Schema Information
#
# Table name: users
#
#  id              :bigint           not null, primary key
#  email           :string           not null
#  username        :string           not null
#  password_digest :string           not null
#  session_token   :string           not null
#  created_at      :datetime         not null
#  updated_at      :datetime         not null
#

require 'securerandom'

class User < ApplicationRecord
  has_secure_password
  validates :username, :password_digest, :session_token, presence: true, uniqueness: true
  validates :username, length: { in: 3..30 }
  validates :email, length: { in: 3..255 }, format: { with: URI::MailTo::EMAIL_REGEXP }
  validates :username, format: { without: URI::MailTo::EMAIL_REGEXP, message: "cant be an email"}
  validates :password, length: { in: 6..255 }, allow_nil: true
  
  before_validation :ensure_session_token

  def self.find_by_credentials(credential, password)
    # determine the field you need to query: 
    #   * `email` if `credential` matches `URI::MailTo::EMAIL_REGEXP`
    #   * `username` if not
    # find the user whose email/username is equal to `credential`
    field = credential.match?(URI::MailTo::EMAIL_REGEXP) ? :email : :username
  
    user = User.find_by(field => credential)
    # if no such user exists, return a falsey value
  
    if user && user.authenticate(password) 
      user
    else
      nil
    end
    # if a matching user exists, use `authenticate` to check the provided password
    # return the user if the password is correct, otherwise return a falsey value
  end

  def reset_session_token!
    # `update!` the user's session token to a new, random token
    # return the new session token, for convenience
    new_session_token = SecureRandom.base64(24)
    self.update!(session_token: new_session_token)
    new_session_token
  end

  private

  def generate_unique_session_token
    loop do
      # Generate a random token using SecureRandom.base64
      session_token = SecureRandom.base64(24)

      # Check if the generated token is already in use
      unless User.exists?(session_token: session_token)
        return session_token  # Return the token if it's unique
      end
    end
  end

  def ensure_session_token
    # if `self.session_token` is already present, leave it be
    # if `self.session_token` is nil, set it to `generate_unique_session_token`
    if !self.session_token 
      self.session_token = generate_unique_session_token
    end
  end

end
