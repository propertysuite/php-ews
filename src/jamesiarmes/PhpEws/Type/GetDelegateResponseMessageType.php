<?php
/**
 * Contains \jamesiarmes\PhpEws\Type\GetDelegateResponseMessageType.
 */

namespace jamesiarmes\PhpEws\Type;

/**
 * Represents the status and result of a GetDelegate operation request.
 *
 * @package php-ews\Types
 */
class GetDelegateResponseMessageType extends BaseDelegateResponseMessageType
{
    /**
     * Defines how meeting requests are handled between the delegate and the
     * principal.
     *
     * @since Exchange 2007 SP1
     *
     * @var \jamesiarmes\PhpEws\Enumeration\DeliverMeetingRequestsType
     */
    public $DeliverMeetingRequests;
}
