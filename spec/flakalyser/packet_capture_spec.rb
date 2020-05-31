# frozen_string_literal: true

RSpec.describe Flakalyser::PacketCapture do
  describe '#events' do
    let :pdml do
      <<-PDML
        <?xml version="1.0" encoding="utf-8"?>
        <?xml-stylesheet type="text/xsl" href="pdml2html.xsl"?>
        <!-- You can find pdml2html.xsl in /usr/local/Cellar/wireshark/3.2.4/share/wireshark or at https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=pdml2html.xsl. -->
        <pdml version="0" creator="wireshark/3.2.4" time="Sun May 31 17:59:00 2020" capture_file="/Users/samk/Downloads/test (1).pcap">
          <packet>
            <proto name="geninfo" pos="0" showname="General information" size="207">
              <field name="num" pos="0" show="8" showname="Number" value="8" size="207"/>
              <field name="len" pos="0" show="207" showname="Frame Length" value="cf" size="207"/>
              <field name="caplen" pos="0" show="207" showname="Captured Length" value="cf" size="207"/>
              <field name="timestamp" pos="0" show="May 30, 2020 10:19:37.866138000 AEST" showname="Captured Time" value="1590797977.866138000" size="207"/>
            </proto>
            <proto name="frame" showname="Frame 8: 207 bytes on wire (1656 bits), 207 bytes captured (1656 bits)" size="207" pos="0">
              <field name="filtered" value="frame" />
            </proto>
            <proto name="eth" showname="Ethernet II, Src: 00:00:00_00:00:00 (00:00:00:00:00:00), Dst: 00:00:00_00:00:00 (00:00:00:00:00:00)" size="14" pos="0">
              <field name="filtered" value="eth" />
            </proto>
            <proto name="ip" showname="Internet Protocol Version 4, Src: 127.0.0.1, Dst: 127.0.0.1" size="20" pos="14">
              <field name="filtered" value="ip" />
            </proto>
            <proto name="tcp" showname="Transmission Control Protocol, Src Port: 36870, Dst Port: 3001, Seq: 1, Ack: 1, Len: 141" size="32" pos="34">
              <field name="filtered" value="tcp" />
            </proto>
            <proto name="http" showname="Hypertext Transfer Protocol" size="141" pos="66">
              <field name="" show="GET /__identify__ HTTP/1.1\r\n" size="28" pos="66" value="474554202f5f5f6964656e746966795f5f20485454502f312e310d0a">
                <field name="_ws.expert" showname="Expert Info (Chat/Sequence): GET /__identify__ HTTP/1.1\r\n" size="0" pos="66">
                  <field name="http.chat" showname="GET /__identify__ HTTP/1.1\r\n" size="0" pos="0" show="" value=""/>
                  <field name="_ws.expert.message" showname="Message: GET /__identify__ HTTP/1.1\r\n" hide="yes" size="0" pos="0" show="GET /__identify__ HTTP/1.1\r\n"/>
                  <field name="_ws.expert.severity" showname="Severity level: Chat" size="0" pos="0" show="2097152"/>
                  <field name="_ws.expert.group" showname="Group: Sequence" size="0" pos="0" show="33554432"/>
                </field>
                <field name="http.request.method" showname="Request Method: GET" size="3" pos="66" show="GET" value="474554"/>
                <field name="http.request.uri" showname="Request URI: /__identify__" size="13" pos="70" show="/__identify__" value="2f5f5f6964656e746966795f5f"/>
                <field name="http.request.version" showname="Request Version: HTTP/1.1" size="8" pos="84" show="HTTP/1.1" value="485454502f312e31"/>
              </field>
              <field name="http.accept_encoding" showname="Accept-Encoding: gzip;q=1.0,deflate;q=0.6,identity;q=0.3\r\n" size="58" pos="94" show="gzip;q=1.0,deflate;q=0.6,identity;q=0.3" value="4163636570742d456e636f64696e673a20677a69703b713d312e302c6465666c6174653b713d302e362c6964656e746974793b713d302e330d0a"/>
              <field name="http.request.line" showname="Accept-Encoding: gzip;q=1.0,deflate;q=0.6,identity;q=0.3\r\n" hide="yes" size="58" pos="94" show="Accept-Encoding: gzip;q=1.0,deflate;q=0.6,identity;q=0.3\xd\xa" value="4163636570742d456e636f64696e673a20677a69703b713d312e302c6465666c6174653b713d302e362c6964656e746974793b713d302e330d0a"/>
              <field name="http.accept" showname="Accept: */*\r\n" size="13" pos="152" show="*/*" value="4163636570743a202a2f2a0d0a"/>
              <field name="http.request.line" showname="Accept: */*\r\n" hide="yes" size="13" pos="152" show="Accept: */*\xd\xa" value="4163636570743a202a2f2a0d0a"/>
              <field name="http.user_agent" showname="User-Agent: Ruby\r\n" size="18" pos="165" show="Ruby" value="557365722d4167656e743a20527562790d0a"/>
              <field name="http.request.line" showname="User-Agent: Ruby\r\n" hide="yes" size="18" pos="165" show="User-Agent: Ruby\xd\xa" value="557365722d4167656e743a20527562790d0a"/>
              <field name="http.host" showname="Host: 127.0.0.1:3001\r\n" size="22" pos="183" show="127.0.0.1:3001" value="486f73743a203132372e302e302e313a333030310d0a"/>
              <field name="http.request.line" showname="Host: 127.0.0.1:3001\r\n" hide="yes" size="22" pos="183" show="Host: 127.0.0.1:3001\xd\xa" value="486f73743a203132372e302e302e313a333030310d0a"/>
              <field name="" show="\r\n" size="2" pos="205" value="0d0a"/>
              <field name="http.request.full_uri" showname="Full request URI: http://127.0.0.1:3001/__identify__" size="0" pos="66" show="http://127.0.0.1:3001/__identify__"/>
              <field name="http.request" showname="Request: True" hide="yes" size="0" pos="66" show="1"/>
              <field name="http.request_number" showname="HTTP request 1/1" size="0" pos="66" show="1"/>
            </proto>
          </packet>
        </pdml>
      PDML
    end

    subject :events do
      Flakalyser::PacketCapture.new(pcap_file: 'pcap-file').events
    end

    before do
      allow(Flakalyser::PacketCapture).to receive(:invoke_tshark).and_return(pdml)
      allow(Flakalyser::PacketCapture::Event).to(
        receive(:new)
          .with(node: a_kind_of(Nokogiri::XML::Element))
          .and_return(instance_double(Flakalyser::PacketCapture::Event))
      )
    end

    it 'returns 1 event' do
      expect(events.length).to eq(1)
      expect(events.all? { |event| event.is_a? Flakalyser::PacketCapture::Event })
    end
  end
end
