module Spree
  Spree::CheckoutController.class_eval do
    #autoload :Helper, 'active_merchant/billing/integrations/redsys/helper.rb'

    before_filter :redirect_to_redsys_form_if_needed, :only => [:update]

    protected

    def redirect_to_redsys_form_if_needed
      return unless (params[:state] == "payment")
      return unless params[:order][:payments_attributes]

      load_order
      #2BeDigital: Cambiamos el número de orden, porque si anulamos y volvemos al banco,
      #redsys da un error de orden repetida. De esta forma, cada vez enviamos una orden distinta
      #a redsys.
      @order.number=Spree::Order.new().generate_order_number()
			OrderUpdateAttributes.new(@order, update_params, request_env: request.headers.env).apply
      @payment_method = Spree::PaymentMethod.find(params[:order][:payments_attributes].first[:payment_method_id])

      return unless @payment_method.kind_of?(Spree::BillingIntegration::RedsysPayment)
      
      @order.payments.destroy_all

      #generamos las urls
      return_url = edit_order_checkout_url(@order, :state => 'payment')
      forward_url = redsys_confirm_order_redsys_callbacks_url(@order, :payment_method_id => @payment_method)
      notify_url = redsys_notify_order_redsys_callbacks_url(@order, :payment_method_id => @payment_method)#, :protocol => 'http')
      notify_url = (@payment_method.preferred_notify_alternative_domain_url + redsys_notify_order_redsys_callbacks_path(@order, :payment_method_id => @payment_method)) if @payment_method.preferred_notify_alternative_domain_url.present?
      #Creamos el objeto redsys que utilizaremos en el formulario.
      @redsys=ActiveMerchant::Billing::Integrations::Redsys.new(@order,@payment_method,return_url,forward_url,notify_url)

      render 'spree/shared/_redsys_payment_checkout', :layout => 'spree_redsys_application'

    end

=begin
    def redsys_credentials (payment_method)
      {
          :terminal_id   => payment_method.preferred_terminal_id,
          :commercial_id => payment_method.preferred_commercial_id,
          :secret_key    => payment_method.preferred_secret_key,
          :key_type      => payment_method.preferred_key_type
      }
    end
=end
  end
end
