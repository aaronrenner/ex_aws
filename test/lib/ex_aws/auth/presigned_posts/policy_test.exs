defmodule ExAws.Auth.PresignedPosts.PolicyTest do
  use ExUnit.Case, async: true

  alias ExAws.Auth.PresignedPosts.Policy

  describe "add_condition/2" do
    test "adding multiple entries retains order" do
      policy =
        Policy.new
        |> Policy.add_condition(%{"acl" => "public-read"})
        |> Policy.add_condition(["starts_with", "$key", "something/"])
        |> Policy.add_condition(%{"Content-Type" => "image/jpeg"})

      assert policy.conditions == [
        %{"acl" => "public-read"},
        ["starts_with", "$key", "something/"],
        %{"Content-Type" => "image/jpeg"},
      ]
    end
  end
end
