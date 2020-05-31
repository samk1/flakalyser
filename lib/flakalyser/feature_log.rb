# frozen_string_literal: true

require('csv')
require('time')

module Flakalyser
  class FeatureLog
    class Event
      def initialize(record:)
        @record = record
      end

      def time
        Time.parse(@record['time'])
      end

      def mock_time
        Time.parse(@record['mock_time']) unless @record['mock_time'].nil?
      end

      def notification_type
        @record['notification_type']
      end

      def description
        @record['description']
      end
    end

    def initialize(log_file:)
      @log_file = log_file
    end

    def events
      @events ||= records.map { |record| Event.new(record: record) }
    end

    private

    def records
      @records ||= table.map(&:to_h)
    end

    def table
      @table ||= csv.readlines
    end

    def csv
      @csv ||= CSV.open(@log_file, headers: true)
    end
  end
end
