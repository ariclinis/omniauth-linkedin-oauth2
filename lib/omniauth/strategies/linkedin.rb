require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class LinkedIn < OmniAuth::Strategies::OAuth2
      option :name, 'linkedin'

      option :client_options, {
        :site => 'https://www.linkedin.com',
        :authorize_url => 'https://www.linkedin.com/oauth/v2/authorization?response_type=code',
        :token_url => 'https://www.linkedin.com/oauth/v2/accessToken'
      }

      option :scope, 'profile email w_member_social'
      option :fields, ['sub', 'name', 'given_name','family_name','picture', 'locale', 'email', 'email_verified']

      uid do
        raw_info['sub']
      end

      info do
        {
          :email => localized_field('email_verified') ? localized_field('email') : "",
          :first_name => localized_field('name'),
          :last_name => localized_field('family_name'),
          :picture_url => localized_field('picture')
        }
      end

      extra do
        {
          'raw_info' => raw_info
        }
      end

      def callback_url
        full_host + script_name + callback_path
      end

      alias :oauth2_access_token :access_token

      def access_token
        ::OAuth2::AccessToken.new(client, oauth2_access_token.token, {
          :expires_in => oauth2_access_token.expires_in,
          :expires_at => oauth2_access_token.expires_at,
          :refresh_token => oauth2_access_token.refresh_token
        })
      end

      def raw_info
        @raw_info ||= self.class.get(profile_endpoint, headers: { 'Authorization' => "Bearer #{access_token}" })
      end

      private

      def fields_mapping
        {
          'sub' => 'sub',
          'name' => 'name',
          'given_name' => 'given_name',
          'family_name' => 'family_name',
          'locale' => 'locale',
          'email' => 'email',
          'email_verified' => 'email_verified',
          'picture' => 'profilePicture(displayImage~:playableStreams)'
        }
      end

      def fields
        options.fields.each.with_object([]) do |field, result|
          result << fields_mapping[field] if fields_mapping.has_key? field
        end
      end

      def localized_field field_name
        raw_info.dig(*[field_name, 'localized', field_locale(field_name)])
      end

      def field_locale field_name
        "#{ raw_info[field_name]['preferredLocale']['language'] }_" \
          "#{ raw_info[field_name]['preferredLocale']['country'] }"
      end

      def picture_url
        return unless picture_available?

        picture_references.last['identifiers'].first['identifier']
      end

      def picture_available?
        raw_info['picture'] &&
          raw_info['picture']['displayImage~'] &&
          picture_references
      end

      def picture_references
        raw_info['picture']['displayImage~']['elements']
      end

      def email_address_endpoint
        '/v2/emailAddress?q=members&projection=(elements*(handle~))'
      end

      def profile_endpoint
        "https://api.linkedin.com/v2/userinfo"
      end
      
      def token_params
        super.tap do |params|
          params.client_secret = options.client_secret
        end
      end
    end
  end
end

OmniAuth.config.add_camelization 'linkedin', 'LinkedIn'
