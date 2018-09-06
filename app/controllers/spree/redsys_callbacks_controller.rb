module Spree
  class RedsysCallbacksController < Spree::BaseController

    skip_before_action :verify_authenticity_token

    #ssl_required

    # Receive a direct notification from the gateway
    # Notificación de ok del gateway. Es la notificación que envia el gateway para dar el cobro como OK.
    def redsys_notify
      logger.debug "==== REDSYS#NOTIFY ==== order##{params[:order_id]} params# #{params.inspect}"
      @order ||= Spree::Order.find_by_number!(params[:order_id])
      #Comprobamos que la signature es correcta.
      notify_acknowledge = acknowledgeSignature(redsys_credentials(payment_method))
      if notify_acknowledge
        #TODO add source to payment
        #Completamos el pago.
        payment_upgrade(params)
        @payment = Spree::Payment.find_by_order_id(@order)
        @payment.complete!
        unless @order.completed?
          #La orden no se "refresca" cuando updatamos el pago,
          #por tanto, la volvemos a coger de la bbdd, y la finalizamos.
          @order = Spree::Order.find_by_number!(params[:order_id])
          order_upgrade()
        end
      else
        #Si la signature no és correcta, simplemente ponemos el pago en processing.
        payment_upgrade(params)
      end
      render :nothing => true
    end


    # Handle the incoming user
    # Captura la "redirección" desde la gateway del banco hacia nuestra web.
    # En principio, se deberia haber recibido antes la notify.
    def redsys_confirm
      logger.debug "==== REDSYS#CONFIRM ==== order##{params[:order_id]} params# #{params.inspect}"
      @order ||= Spree::Order.find_by_number!(params[:order_id])
      unless @order.completed?
        #La orden no se ha completado. Quiere decir que no hemos recibido el notify.
        #Ponemos el pago en processing, y finalizamos la orden, que nos quedará
        #como "balance_due"
        payment_upgrade(params)
        @order = Spree::Order.find_by_number!(params[:order_id])
        order_upgrade()
      end
      # Unset the order id as it's completed.
      session[:order_id] = nil #deprecated from 2.3
      flash.notice = Spree.t(:order_processed_successfully)
      flash['order_completed'] = true
      redirect_to order_path(@order)
    end

    #Fusilado de taniarv
    #https://github.com/taniarv/spree_redsys/blob/7242fd7c1c206e87d8bc0e38a679853a50a171c7/app/controllers/spree/redsys_callbacks_controller.rb
    #No tengo claro que esta notificacion llegue alguna vez, pero por si acaso...
    def redsys_error
      logger.debug "==== REDSYS#ERROR ==== order##{params[:order_id]} params# #{params.inspect}"
      notify_acknowledge = acknowledgeSignature(redsys_credentials(payment_method))
      if notify_acknowledge
        @order ||= Spree::Order.find_by_number!(params[:order_id])
        @order.update_attribute(:payment_state, 'failed')
        flash[:alert] = Spree.t(:spree_gateway_error_flash_for_checkout)
      end
      redirect_to order_path(@order)
    end

    def redsys_credentials (payment_method)
      {
          :terminal_id   => payment_method.preferred_terminal_id,
          :commercial_id => payment_method.preferred_commercial_id,
          :secret_key    => payment_method.preferred_secret_key,
          :key_type      => payment_method.preferred_key_type
      }
    end

    #Crea un pago y lo pone en estado processing.
    def payment_upgrade (params)
			decodec = decode_Merchant_Parameters || Array.new
      payment = @order.payments.create!({:amount => @order.total,
                                        :payment_method => payment_method,
                                        :response_code => decodec.include?('Ds_Response')? decodec['Ds_Response'].to_s : nil,
                                        :avs_response => decodec.include?('Ds_AuthorisationCode')? decodec['Ds_AuthorisationCode'].to_s : nil})
      payment.started_processing!
      #@order.update(:considered_risky => 0) if no_risky
    end

    def payment_method
      @payment_method ||= Spree::PaymentMethod.find(params[:payment_method_id])
      @payment_method ||= Spree::PaymentMethod.find_by_type("Spree::BillingIntegration::redsysPayment")
    end
    #Completa y finaliza la orden.
    def order_upgrade
      @order.next
      @order.complete!
      # Since we dont rely on state machine callback, we just explicitly call this method for spree_store_credits
      if @order.respond_to?(:consume_users_credit, true)
        @order.send(:consume_users_credit)
      end
      @order.finalize!
    end

    protected

    def decode_Merchant_Parameters
      return nil if(params[:Ds_MerchantParameters].blank?)
      jsonrec = Base64.urlsafe_decode64(params[:Ds_MerchantParameters])
      JSON.parse(jsonrec)
    end

    def create_MerchantSignature_Notif(key)
      keyDecoded=Base64.decode64(key)

      #obtenemos el orderId.
      orderrec = (decode_Merchant_Parameters['Ds_Order'].blank?)? decode_Merchant_Parameters['DS_ORDER'] : decode_Merchant_Parameters['Ds_Order']

      key3des=des3key(keyDecoded, orderrec)
      hmac=hmac(key3des,params[:Ds_MerchantParameters])
      sign=Base64.urlsafe_encode64(hmac)
    end


    def acknowledgeSignature(credentials = nil)
      return false if(params[:Ds_SignatureVersion].blank? ||
          params[:Ds_MerchantParameters].blank? ||
          params[:Ds_Signature].blank?)

      #HMAC_SHA256_V1
      return false if(params[:Ds_SignatureVersion] != credentials[:key_type])

      decodec = decode_Merchant_Parameters
      create_Signature = create_MerchantSignature_Notif(credentials[:secret_key])
			Rails.logger.debug "RedsysChekcout: JSON Decodec: #{decodec}"
      msg =
          "REDSYS_NOTIFY: " +
              " ---- Ds_Response: " + decodec['Ds_Response'].to_s +
              " ---- order_TS: " + decodec['Ds_Order'].to_s +
              " ---- order_Number: " + @order.number +
              " ---- Signature: " + create_Signature.to_s.upcase +
              " ---- Ds_Signature " + params[:Ds_Signature].to_s.upcase +
              " ---- RESULT " + ((create_Signature.to_s.upcase == params[:Ds_Signature].to_s.upcase)? 'OK' : 'KO')
      Rails.logger.debug "#{msg}"

      res=create_Signature.to_s.upcase == params[:Ds_Signature].to_s.upcase
			
			responseCode=decodec['Ds_Response'].to_i
			Rails.logger.debug "Ds_ResponseInt: #{responseCode}"
			
			#Potser és una mica rebuscat, però comprovem primer la signature perquè si un señor
			#maligno envia una petició fake amb Ds_Response d'error, estariem denegant la compra
			#sense comprovar que la request és correcte.
			#Segons la doc, els codis OKs poden anar de 0000 a 0099 o 900 per a devolucions.
			return false if (responseCode > 99 && responseCode!=900)
			res
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

