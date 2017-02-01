require 'yajl'
require 'securerandom' # SecureRandom.uuid 

require_relative 'oms_common'

module OMS
    class AuditdPlugin

        def initialize(log)
            @log = log
        end

        def transform_and_wrap(record, hostname, time)
            if record.nil?
                @log.error "Transformation of Auditd Plugin input failed; Empty input"
                return nil
            end

            if !record.has_key?("record-count")
                @log.error "Transformation of Auditd Plugin input failed; Missing field 'record-count'"
                return nil
            end

            if record["record-count"] <= 0
                @log.error "Transformation of Auditd Plugin input failed; Invalid 'record-count' value"
                return nil
            end

            records = []

            for ridx in 1..record["record-count"]
                rname = "record-data-"+(ridx-1).to_s
                if !record.has_key?(rname)
                    @log.error "Transformation of Auditd Plugin input failed; Missing field '" + rname + "'"
                    return nil
                end
                rdata = Yajl::Parser.parse(record[rname])
                rdata["Timestamp"] = OMS::Common.format_time(record["AuditID"].to_f)
                rdata["AuditID"] = record["AuditID"]
                rdata["SerialNumber"] = record["SerialNumber"]
                rdata["Computer"] = hostname
                records.push(rdata)
            end

            wrapper = {
                "DataType"=>"LINUX_AUDITD_BLOB",
                "IPName"=>"Security",
                "DataItems"=>records
            }

            @log.info "Audit Event Processed"

            return wrapper
        end

    end # class
end # module
