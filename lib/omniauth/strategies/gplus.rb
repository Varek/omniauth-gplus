require 'omniauth/strategies/oauth2'

module OmniAuth
  module Strategies
    class GPlus < OmniAuth::Strategies::OAuth2
      class NoAuthorizationCodeError < StandardError; end
      class UnknownSignatureAlgorithmError < NotImplementedError; end

      option :client_options,
             :site => 'https://www.googleapis.com/plus/v1',
             :authorize_url => 'https://www.google.com/accounts/o8/oauth2/authorization',
             :token_url => 'https://www.google.com/accounts/o8/oauth2/token'

      option :authorize_options, [:scope, :request_visible_actions]

      option :scope, 'email'

      option :request_visible_actions, nil

      option :uid_field, :uid

      uid { raw_info['id'] }

      info do
        {
          'email' => raw_info['emails'].first['value'],
          'name' => raw_info['displayName'],
          'first_name' => raw_info['name']['givenName'],
          'last_name' => raw_info['name']['familyName'],
          'image' => raw_info['image']['url'],
          'urls' => {
            'Google+' => raw_info['url']
          }
        }
      end

      extra do
        {
          'gender' => raw_info['gender'],
          'birthday' => raw_info['birthday'],
          'raw_info' => raw_info
        }
      end

      def authorize_params
        super.tap do |params|
          params['scope'] = format_scopes(params['scope'])
          params['request_visible_actions'] = format_actions(params['request_visible_actions']) if params['request_visible_actions']
          custom_parameters(params)
        end
      end

      private

      def format_actions(actions)
        actions.split(/,\s*/).collect(&method(:format_action)).join(' ')
      end

      def format_action(action)
        "http://schemas.google.com/#{action}"
      end

      def format_scopes(scopes)
        scopes.split(/,\s*/).collect(&method(:format_scope)).join(' ')
      end

      def format_scope(scope)
		return scope if ['profile','email','openid'].include?(scope)
        "https://www.googleapis.com/auth/#{scope}"
      end

      def custom_parameters(params)
        %w(scope client_options request_visible_actions access_type).each { |k| add_key_to_params(params, k) }
      end

      def add_key_to_params(params, key)
        params[key] = request.params[key] if request.params[key]
      end

      def raw_info
        access_token.options[:mode] = :query
        @raw_info ||= access_token.get('people/me').parsed
      end
    end
  end
end
