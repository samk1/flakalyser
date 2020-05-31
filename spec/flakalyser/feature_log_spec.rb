# frozen_string_literal: true

RSpec.describe Flakalyser::FeatureLog do
  describe '#events' do
    let :csv do
      <<-CSV
        time,mock_time,notification_type,description
        2020-05-31T05:16:56.717849412+00:00,,example_group_started,Connect and integrate with Xero
        2020-05-31T05:16:56.717995437+00:00,,example_group_started,Fresho has a Xero app with a client id and secret
        2020-05-31T05:16:56.718051901+00:00,,example_group_started,A Supplier is configured to send invoice updates to Xero
        2020-05-31T05:16:56.718113355+00:00,,example_group_started,And they are set up to sell priced products
        2020-05-31T05:16:56.718236489+00:00,,example_started,Sending invoices to Xero without Xero configuration causes errors
      CSV
    end

    subject :events do
      Flakalyser::FeatureLog.new(log_file: 'log-file').events
    end

    before do
      allow(CSV).to receive(:open).with('log-file', headers: true).and_return(CSV.new(csv, headers: true))
      allow(Flakalyser::FeatureLog::Event).to(
        receive(:new).and_return(instance_double(Flakalyser::FeatureLog::Event))
      )
    end

    it 'returns 5 events' do
      expect(events.length).to eq(5)
      expect(events.all? { |event| event.is_a? Flakalyser::FeatureLog::Event })
    end
  end
end
