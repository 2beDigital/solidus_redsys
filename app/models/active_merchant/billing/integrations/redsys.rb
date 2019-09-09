# encoding: utf-8
module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    module Integrations #:nodoc:
      #Clase que utilizamos en el formulario de envío de datos al banco.
      class Redsys

        attr_accessor :Ds_SignatureVersion
        attr_accessor :Ds_MerchantParameters
        attr_accessor :Ds_Signature
        attr_accessor :credentials
        attr_accessor :integration_mode

        @@service_test_url = "https://sis-t.redsys.es:25443/sis/realizarPago"
        @@service_production_url = "https://sis.redsys.es/sis/realizarPago"

        @@operations_test_url = "https://sis-t.redsys.es:25443/sis/operaciones"
        @@operations_production_url = "https://sis.redsys.es/sis/operaciones"

        def initialize(order, payment_method, return_url, forward_url, notify_url)
          @integration_mode = :production
          @order=order
          @payment_method=payment_method
          @credentials=redsys_credentials (@payment_method)
          #Ds_Merchant_MerchantURL
          if @payment_method.kind_of?(Spree::BillingIntegration::RedsysPayment) && @payment_method.preferred_test_mode
            @integration_mode = :test
          end
          @redsysparams = {
              :Ds_Merchant_Order => @order.number[1..9],
              :Ds_Merchant_MerchantName => Spree::Store.default.name,
              :Ds_Merchant_Amount => (@payment_method.amount_in_cents(@order.total)),
              :Ds_Merchant_Currency => currency_code( @payment_method.preferred_currency),
              :Ds_Merchant_MerchantCode => @credentials[:commercial_id],
              :Ds_Merchant_Terminal => @credentials[:terminal_id],
              :Ds_Merchant_TransactionType => transaction_code(:authorization), # Default Transaction Type
              :Ds_Merchant_ProductDescription => get_description(),#options[:description],
              :Ds_Merchant_Titular => "#{@order.ship_address.firstname} #{@order.ship_address.lastname}",
              :Ds_Merchant_ConsumerLanguage => language_code(I18n.locale),
              :Ds_Merchant_UrlKO => return_url,
              :Ds_Merchant_UrlOK => forward_url,
              :Ds_Merchant_MerchantURL => notify_url
          }
        end

        def redsys_credentials (payment_method)
          {
            :terminal_id   => payment_method.preferred_terminal_id,
            :commercial_id => payment_method.preferred_commercial_id,
            :secret_key    => payment_method.preferred_secret_key,
            :key_type      => payment_method.preferred_key_type
          }
        end

        def service_url
          case @integration_mode
          when :production
            @@service_production_url
          when :test
            @@service_test_url
          else
            raise StandardError, "Integration mode set to an invalid value: #{mode}"
          end
        end

        def operations_url
          #mode = ActiveMerchant::Billing::Base.integration_mode
          case @integration_mode
          when :production
            @@operations_production_url
          when :test
            @@operations_test_url
          else
            raise StandardError, "Integration mode set to an invalid value: #{mode}"
          end
        end

        def currency_code( name )
          row = supported_currencies.assoc(name)
          row.nil? ? supported_currencies.first[1] : row[1]
        end

        def create_Merchant_Parameters
          Base64.strict_encode64(@redsysparams.to_json)
        end

        # Generate a signature authenticating the current request.
        def create_Merchant_Signature
          key = credentials[:secret_key]
          keyDecoded=Base64.decode64(key)
          key3des=des3key(keyDecoded,@redsysparams[:Ds_Merchant_Order])
          hmac=hmac(key3des,create_Merchant_Parameters)
          sign=Base64.strict_encode64(hmac)
        end

        def transaction_code(name)
          row = supported_transactions.assoc(name.to_sym)
          row.nil? ? supported_transactions.first[1] : row[1]
        end

        def language_code(name)
          row = supported_languages.assoc(name.to_s.downcase.to_sym)
          row.nil? ? supported_languages.first[1] : row[1]
        end

        def supported_currencies
          [ ['EUR', '978'], ['CHF', '756'], ['USD', '840'] ]
        end

        def supported_languages
          [
            [:es, '001'],
            [:en, '002'],
            [:ca, '003'],
            [:fr, '004'],
            [:de, '005'],
            [:pt, '009']
          ]
        end

        def supported_transactions
          [
            [:authorization,              '0'],
            [:preauthorization,           '1'],
            [:confirmation,               '2'],
            [:automatic_return,           '3'],
            [:reference_payment,          '4'],
            [:recurring_transaction,      '5'],
            [:successive_transaction,     '6'],
            [:authentication,             '7'],
            [:confirm_authentication,     '8'],
            [:cancel_preauthorization,    '9'],
            [:deferred_authorization,             'O'],
            [:confirm_deferred_authorization,     'P'],
            [:cancel_deferred_authorization,      'Q'],
            [:inicial_recurring_authorization,    'R'],
            [:successive_recurring_authorization, 'S']
          ]
        end

        def response_code_message(code)
          case code.to_i
          when 0..99
            nil
          when 900
           "Transacción autorizada para devoluciones y confirmaciones"
          when 101
            "Tarjeta caducada"
          when 102
            "Tarjeta en excepción transitoria o bajo sospecha de fraude"
          when 104
            "Operación no permitida para esa tarjeta o terminal"
          when 116
            "Disponible insuficiente"
          when 118
            "Tarjeta no registrada o Método de pago no disponible para su tarjeta"
          when 129
            "Código de seguridad (CVV2/CVC2) incorrecto"
          when 180
            "Tarjeta no válida o Tarjeta ajena al servicio o Error en la llamada al MPI sin controlar."
          when 184
            "Error en la autenticación del titular"
          when 190
            "Denegación sin especificar Motivo"
          when 191
            "Fecha de caducidad errónea"
          when 202
            "Tarjeta en excepción transitoria o bajo sospecha de fraude con retirada de tarjeta"
          when 912,9912
            "Emisor no disponible"
          when 913
            "Pedido repetido"
          else
            "Transacción denegada"
          end
        end

        private

        def get_description()
          items = @order.line_items.map do |item|
            price = (item.price * 100).to_i # convert for gateway
            { Spree.t(:name)        => item.variant.product.name,
              #Héctor Note 10/12/2014 Commeted to avoid html tags t(:description) => (item.variant.product.description[0..20]+"..." if item.variant.product.description),
              Spree.t(:qty)    => item.quantity
            }
          end
          items.to_s[0..120].gsub(/({|")/,'').gsub(/}/,"\n").gsub("=>",": ").gsub("[","(").gsub("]",")")
        end

        def des3key(key,message)
          block_length = 8
          cipher = OpenSSL::Cipher::Cipher.new("des-ede3-cbc")
          cipher.padding = 0
          cipher.encrypt
          cipher.key = key
          message += "\0" until message.bytesize % block_length == 0
          ciphertext = cipher.update(message)
          ciphertext << cipher.final
          ciphertext
        end

        def hmac(key,message)
          hash  = OpenSSL::HMAC.digest('sha256', key, message)
        end

      end
    end
  end
end
