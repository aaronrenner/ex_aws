defmodule ExAws.Auth.PresignedPosts.PresignedPost do

  def new do
    %{fields: %{}, policy: Policy.new }
  end

  def put_field(presigned_post, field_name, value) do
  end

  def fields_with_signature(presigned_post) do
  end
end
