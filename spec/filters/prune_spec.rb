require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/prune"

# Currently the prune filter has bugs and I can't really tell what the intended
# behavior is.
#
# See the 'whitelist field values with interpolation' test for a commented
# explanation of my confusion.
describe LogStash::Filters::Prune do
  subject { described_class.new(config) }
  let(:config) { {} }
  let(:event_data) do
    {
      "firstname"    => "Borat",
      "lastname"     => "Sagdiyev",
      "fullname"     => "Borat Sagdiyev",
      "country"      => "Kazakhstan",
      "location"     => "Somethere in Kazakhstan",
      "hobby"        => "Cloud",
      "status"       => "200",
      "Borat_saying" => "Cloud is not ready for enterprise if is not integrate with single server running Active Directory.",
    }
  end

  let(:event) { LogStash::Event.new(event_data) }

  before(:each) do
    subject.register
    subject.filter(event)
  end

  describe "default behaviour" do
    it "retains all fields since whiteliste_names is empty" do
      expect(event.to_hash.keys).to include(*event_data.keys)
    end
    describe "blacklist_names" do
      let(:event_data) { super.merge("%{hmm}" => "doh") }
      it "drops unresolved field references" do
        expect(event.get("%{hmm}")).to be_nil
      end
    end
  end

  describe "whitelist_names" do

    let(:config) do
      { "whitelist_names" => [ "firstname", "(hobby|status)", "%{firstname}_saying" ] }
    end

    it "keeps fields in the list" do
      expect(event.get("firstname")).to eq("Borat")
      expect(event.get("hobby")).to eq("Cloud")
      expect(event.get("status")).to eq("200")
    end

    it "drops fields not described in the whitelist" do
      expect(event.get("lastname")).to be_nil
      expect(event.get("fullname")).to be_nil
      expect(event.get("country")).to be_nil
      expect(event.get("location")).to be_nil
      expect(event.get("Borat_saying")).to be_nil
      expect(event.get("%{hmm}")).to be_nil
    end

    context "with interpolation" do

      let(:config) do
        {
          "whitelist_names" => [ "firstname", "%{firstname}_saying" ],
          "interpolate" => true
        }
      end

      it "retains fields that match after interpolation" do
        expect(event.get("firstname")).to eq("Borat")
        expect(event.get("Borat_saying")).to eq("Cloud is not ready for enterprise if is not integrate with single server running Active Directory.")
      end
    end
  end

  describe "blacklist_names" do

    let(:config) do
      { "blacklist_names" => [ "firstname", "(hobby|status)", "%{firstname}_saying" ] }
    end

    it "drops fields in the list" do
      expect(event.get("firstname")).to eq(nil)
      expect(event.get("hobby")).to eq(nil)
      expect(event.get("status")).to eq(nil)
    end

    it "keeps the remaining fields" do
      expect(event.get("lastname")).to eq("Sagdiyev")
      expect(event.get("fullname")).to eq("Borat Sagdiyev")
      expect(event.get("country")).to eq("Kazakhstan")
      expect(event.get("location")).to eq("Somethere in Kazakhstan")
      expect(event.get("Borat_saying")).to eq("Cloud is not ready for enterprise if is not integrate with single server running Active Directory.")
    end

    context "if there are non resolved field references" do
      let(:event_data) { super.merge("%{hmm}" => "doh") }
      it "also drops them" do
        expect(event.get("%{hmm}")).to eq("doh")
      end
    end
    context "with interpolation" do

      let(:config) { super.merge("interpolate" => true) }

      it "drops fields after interpolation" do
        expect(event.get("Borat_saying")).to be_nil
      end
    end
  end
  describe "whitelist_values" do

    let(:config) do
      {
        # This should only  permit fields named 'firstname', 'fullname',
        # 'location', 'status', etc.
        "whitelist_values" => {
          "firstname" => "^Borat$",
          "fullname" => "%{firstname} Sagdiyev",
          "location" => "no no no",
          "status" => "^2",
          "%{firstname}_saying" => "%{hobby}.*Active"
        }
      }
    end

    it "keeps fields in the whitelist if the value matches" do
      expect(event.get("firstname")).to eq("Borat")
      expect(event.get("status")).to eq("200")
    end

    it "drops fields in the whitelist if the value doesn't match" do
      expect(event.get("fullname")).to be_nil
      expect(event.get("location")).to be_nil
    end

    it "include all other fields" do
      # whitelist_values will only filter configured fields
      # all others are still governed by the whitelist_names setting
      # which means they're all kept by default
      expect(event.get("lastname")).to eq("Sagdiyev")
      expect(event.get("country")).to eq("Kazakhstan")
      expect(event.get("hobby")).to eq("Cloud")
      expect(event.get("Borat_saying")).to eq("Cloud is not ready for enterprise if is not integrate with single server running Active Directory.")
    end

    context "with interpolation" do

      let(:config) do
        {
          "whitelist_values" => {
            "firstname" => "^Borat$",
            "fullname" => "%{firstname} Sagdiyev",
            "location" => "no no no",
            "status" => "^2",
            "%{firstname}_saying" => "%{hobby}.*Active"
          },
          "interpolate" => true
        }
      end
      let(:event_data) { super.merge("%{hmm}" => "doh") }
      it "keeps field values after interpolation" do
        expect(event.get("fullname")).to eq("Borat Sagdiyev")
        expect(event.get("Borat_saying")).to eq("Cloud is not ready for enterprise if is not integrate with single server running Active Directory.")
      end
    end
    context "with array values" do

      let(:config) do
        {
          "whitelist_values" => {
            "status" => "^(1|2|3)",
            "xxx" => "3",
            "error" => "%{blah}"
          }
        }
      end

      let(:event_data) do
        {
          "blah"   => "foo",
          "xxx" => [ "1 2 3", "3 4 5" ],
          "status" => [ "100", "200", "300", "400", "500" ],
          "error"  => [ "This is foolish" , "Need smthing smart too" ]
        }
      end

      it "drops fields if no value matches" do
        expect(event.get("error")).to eq(nil)
      end

      it "keeps only elements that match" do
        expect(event.get("status")).to eq([ "100", "200", "300" ])
      end

      it "keeps values intact if they all match" do
        expect(event.get("xxx")).to eq([ "1 2 3", "3 4 5" ])
      end
      context "with interpolation" do
        let(:config) { super.merge("interpolate" => true) }
        it "keeps values that match after interpolation" do
          expect(event.get("error")).to eq([ "This is foolish" ])
        end
      end
    end
  end

  describe "blacklist_values" do

    let(:config) do
      {
        "blacklist_values" => {
          "firstname" => "^Borat$",
          "fullname" => "%{firstname} Sagdiyev",
          "location" => "no no no",
          "status" => "^2",
          "%{firstname}_saying" => "%{hobby}.*Active"
        }
      }
    end

    it "drops fields that match the values" do
      expect(event.get("firstname")).to eq(nil)
      expect(event.get("status")).to eq(nil)
    end

    it "keeps fields that don't match the values" do
      expect(event.get("fullname")).to eq("Borat Sagdiyev")
      expect(event.get("location")).to eq("Somethere in Kazakhstan")
    end

    context "with interpolation" do

      let(:config) { super.merge("interpolate" => true) }

      it "drops fields that match after interpolation" do
        expect(event.get("fullname")).to eq(nil)
        expect(event.get("Borat_saying")).to eq(nil)
      end
    end
    context "with array values" do

      let(:config) do
        {
          "blacklist_values" => {
            "status" => "^(1|2|3)",
            "xxx" => "3",
            "error" => "%{blah}"
          }
        }
      end
      let(:event_data) do
        {
          "blah"   => "foo",
          "xxx" => [ "1 2 3", "3 4 5" ],
          "status" => [ "100", "200", "300", "400", "500" ],
          "error"  => [ "This is foolish", "Need smthing smart too" ]
        }
      end
      it "drops fields if no elements match" do
        expect(event.get("xxx")).to eq(nil)
      end

      it "keeps values that don't match" do
        expect(event.get("error")).to eq([ "This is foolish", "Need smthing smart too" ])
        expect(event.get("status")).to eq([ "400", "500" ])
      end

      context "with interpolation" do
        let(:config) { super.merge("interpolate" => true) }
        it "drops values that match after interpolation" do
          expect(event.get("error")).to eq([ "Need smthing smart too" ])
        end
      end
    end
  end
end
