module Spree
  Spree::CheckoutController.class_eval do
    before_filter :redirect_to_sermepa_form_if_needed, :only => [:update]

    private

    def redirect_to_sermepa_form_if_needed
      return unless (params[:state] == "payment")
      return unless params[:order][:payments_attributes]

      if @order.update_attributes(object_params)
        if params[:order][:coupon_code] and !params[:order][:coupon_code].blank? and @order.coupon_code.present?
          fire_event('spree.checkout.coupon_code_added', :coupon_code => @order.coupon_code)
        end
      end

      load_order_with_lock
      @payment_method = Spree::PaymentMethod.find(params[:order][:payments_attributes].first[:payment_method_id])

      ## Fixing double payment creation ##
      if @payment_method.kind_of?(Spree::PaymentMethod::Check) ||
         @payment_method.kind_of?(Spree::BillingIntegration::SermepaPayment) ||
         @payment_method.kind_of?(Spree::BillingIntegration::CecaPayment)
        @order.payments.destroy_all
      end

      if @payment_method.kind_of?(Spree::BillingIntegration::SermepaPayment)

        @payment_method.provider_class::Helper.credentials = sermepa_credentials(@payment_method)
        #set_cache_buster
        render 'spree/shared/_sermepa_payment_checkout', :layout => 'spree_sermepa_application'
      else if @payment_method.kind_of?(Spree::BillingIntegration::CecaPayment)

            @payment_method.provider_class::Helper.credentials = ceca_credentials(@payment_method)

            render 'spree/shared/_ceca_payment_checkout', :layout => 'spree_sermepa_application'
          end
      end
    end

    def sermepa_credentials (payment_method)
      {
          :terminal_id   => payment_method.preferred_terminal_id,
          :commercial_id => payment_method.preferred_commercial_id,
          :secret_key    => payment_method.preferred_secret_key,
          :key_type      => payment_method.preferred_key_type
      }
    end

    def ceca_credentials (payment_method)
      {
          :AcquirerBIN   => payment_method.preferred_AcquirerBIN,
          :MerchantID    => payment_method.preferred_MerchantID,
          :TerminalID    => payment_method.preferred_TerminalID,
          :secret_key    => payment_method.preferred_secret_key,
          :key_type      => payment_method.preferred_key_type
      }
    end


    def user_locale
      I18n.locale.to_s
    end

    def sermepa_gateway
      payment_method.provider
    end

    def set_cache_buster
      response.headers["Cache-Control"] = "no-cache, no-store" #post-check=0, pre-check=0
      response.headers["Pragma"] = "no-cache"
      response.headers["Expires"] = "Fri, 01 Jan 1990 00:00:00 GMT"
    end


  end

end
