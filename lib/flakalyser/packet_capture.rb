# frozen_string_literal: true

require('nokogiri')

module Flakalyser
  class PacketCapture
    class Event
      def initialize(packet_node:)
        @packet_node = packet_node
      end
    end

    def initialize(pcap_file:)
      @pcap_file = pcap_file
    end

    def events
      packet_nodes.map { |packet_node| Event.new(node: packet_node) }
    end

    def self.invoke_tshark(pcap_file)
      `tshark -r #{@pcap_file} -Y http -T pdml -J http`
    end

    private

    def packet_nodes
      @packets ||= pdml.xpath('/pdml/packet')
    end

    def pdml
      @pdml ||= Nokogiri::XML(tshark_output)
    end

    def tshark_output
      @tshark_output ||= PacketCapture.invoke_tshark(@pcap_file)
    end
  end
end
