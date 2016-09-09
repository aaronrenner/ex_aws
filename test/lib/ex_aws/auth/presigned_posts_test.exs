defmodule ExAws.Auth.PresignedPostsTest do
  use ExUnit.Case, async: true

  import ExAws.Auth.Utils
  alias ExAws.Auth.{Credentials, Signatures}

  test "generate_presigned_post with default arguments" do
    config = ExAws.Config.new(:s3, [
      access_key_id: "AKIAIOSFODNN7EXAMPLE",
      secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      region: "us-east-1"
    ])
    bucket_name = "my-test-bucket"
    key = "my-test-folder/${filename}"
    datetime = {{2016,8,29},{19,41,33}}

    result = ExAws.Auth.PresignedPosts.generate_presigned_post(config, bucket_name, key, current_datetime: datetime)

    expected_policy = %{
      "expiration" => datetime |> ExAws.Utils.add_seconds(3600) |> iso_8601_format,
      "conditions" => [
        %{"bucket" => bucket_name},
        [
          "starts-with",
          "$key",
          "my-test-folder/"
        ],
        %{"x-amz-algorithm" => "AWS4-HMAC-SHA256"},
        %{"x-amz-credential" => "#{config.access_key_id}/20160829/#{config.region}/s3/aws4_request"},
        %{"x-amz-date" => amz_date(datetime)},
      ],
    } |> config.json_codec.encode! |> Base.encode64

    assert result == %{
      url: "#{config.scheme}#{bucket_name}.#{config.host}",
      form_fields: %{
        "key" => key,
        "x-amz-date" => amz_date(datetime),
        "x-amz-algorithm" => "AWS4-HMAC-SHA256",
        "x-amz-credential" => Credentials.generate_credential_v4("s3", config, datetime),
        "x-amz-signature" =>  Signatures.generate_signature_v4("s3", config, datetime, expected_policy),
        "policy" => expected_policy
      }
    }
  end

  # test "generate_presigned_post with additional options" do
  #   config = ExAws.Config.new(:s3, [
  #     access_key_id: "AKIAIOSFODNN7EXAMPLE",
  #     secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  #     region: "us-east-1"
  #   ])
  #   bucket_name = "my-test-bucket"
  #   key = "my-test-folder/${filename}"
  #   datetime = {{2016,8,29},{19,41,33}}
  #
  #   result = ExAws.Auth.PresignedPosts.generate_presigned_post(
  #     config,
  #     bucket_name,
  #     key,
  #     fields: [{"content-type", "application/json"},{"acl" => "public-read"}]
  #     current_datetime: datetime)
  #
  #   assert result == %{
  #     url: "#{config.scheme}#{bucket_name}.#{config.host}",
  #     form_fields: %{
  #       "key" => key,
  #       "content-type" => "application/json",
  #       "acl" => "public-read",
  #       "x-amz-date" => amz_date(datetime),
  #       "x-amz-algorithm" => "AWS4-HMAC-SHA256",
  #       "x-amz-credential" => Credentials.generate_credential_v4("s3", datetime, config),
  #       "x-amz-signature" => "51a363898bb0d82cb739003f440ec6ca33ca27dd8997050cae2dbf736cc02219",
  #       "policy" => %{
  #         "expiration" => datetime |> ExAws.Utils.add_seconds(3600) |> iso_8601_format,
  #         "conditions" => [
  #           %{"bucket" => bucket_name},
  #           %{"content-type" => "application/json"},
  #           %{"acl" => "public-read"},
  #           [
  #             "starts-with",
  #             "$key",
  #             "my-test-folder/"
  #           ],
  #           %{"x-amz-algorithm" => "AWS4-HMAC-SHA256"},
  #           %{"x-amz-credential" => "#{config.access_key_id}/20160829/#{config.region}/s3/aws4_request"},
  #           %{"x-amz-date" => amz_date(datetime)},
  #         ],
  #       } |> config.json_codec.encode! |> Base.encode64,
  #     }
  #   }
  # end
end
